#include "rustbgpd_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

#include <grpcpp/grpcpp.h>

#include <boost/algorithm/string.hpp>

#include "../bgp_protocol.hpp"

#include "../rustbgpd_client/rustbgpd_injection.grpc.pb.h"

#include "../fastnetmon_configuration_scheme.hpp"

extern fastnetmon_configuration_t fastnetmon_global_configuration;

// rustbgpd action: announces and withdraws blackholes through rustbgpd's InjectionService
// https://github.com/lance0/rustbgpd/blob/main/docs/reference/api.md#injectionservice
//
// Routes injected into rustbgpd live only as long as the rustbgpd process. We keep every
// active ban here and announce all of them again when rustbgpd becomes reachable after a
// failed liveness probe (as after a rustbgpd restart) and on a periodic reconcile pass.

// Deadline for AddPath, DeletePath and RenewLease calls
unsigned int rustbgpd_call_timeout = 5;

// How often we probe rustbgpd with ControlService.CheckLiveness
const std::chrono::milliseconds rustbgpd_probe_interval(500);

class rustbgpd_route_t {
    public:
    std::string prefix;
    uint32_t prefix_length = 0;
    std::string next_hop;
    std::vector<uint32_t> communities;

    std::string key() const {
        return prefix + "/" + std::to_string(prefix_length);
    }
};

std::unique_ptr<rustbgpd::v1::InjectionService::Stub> rustbgpd_injection_stub;
std::unique_ptr<rustbgpd::v1::ControlService::Stub> rustbgpd_control_stub;

std::string rustbgpd_token;

// Serialises all calls which change routes in rustbgpd with changes of our own ban lists
std::mutex rustbgpd_mutex;

// Bans which must be announced
std::map<std::string, rustbgpd_route_t> rustbgpd_active_routes;

// Withdrawals which have not succeeded yet
std::map<std::string, rustbgpd_route_t> rustbgpd_pending_withdrawals;

// Set when a call failed because rustbgpd was not reachable or when our lease is gone
bool rustbgpd_reconcile_needed = false;

// Lease generation returned by the last leased add
bool rustbgpd_lease_generation_known = false;
rustbgpd::v1::LeaseGeneration rustbgpd_lease_generation;

void rustbgpd_prepare_context(grpc::ClientContext& context, unsigned int timeout_seconds) {
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(timeout_seconds));

    // Call credentials are attached only to channels gRPC considers secure, so we add token directly to each call
    if (!rustbgpd_token.empty()) {
        context.AddMetadata("authorization", "Bearer " + rustbgpd_token);
    }
}

std::string rustbgpd_describe_status(const grpc::Status& status) {
    return "code " + std::to_string(status.error_code()) + ": " + status.error_message();
}

// Errors after which an immediate retry makes sense
bool rustbgpd_is_transient_error(const grpc::Status& status) {
    return status.error_code() == grpc::StatusCode::UNAVAILABLE || status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED;
}

// Must be called with rustbgpd_mutex held
bool rustbgpd_add_route(const rustbgpd_route_t& route) {
    rustbgpd::v1::AddPathRequest path;

    path.set_prefix(route.prefix);
    path.set_prefix_length(route.prefix_length);
    path.set_next_hop(route.next_hop);

    // Same origin as GoBGP action announces
    path.set_origin(BGP_ORIGIN_INCOMPLETE);

    for (auto community : route.communities) {
        path.add_communities(community);
    }

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    grpc::Status status;
    rustbgpd::v1::PathInjectOutcome outcome = rustbgpd::v1::PATH_INJECT_OUTCOME_UNSPECIFIED;

    if (fastnetmon_global_configuration.rustbgpd_lease) {
        rustbgpd::v1::AddLeasedPathRequest request;
        *request.mutable_path() = path;
        request.mutable_lease()->set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
        request.mutable_lease()->set_lease_seconds(fastnetmon_global_configuration.rustbgpd_lease_time);

        rustbgpd::v1::AddLeasedPathResponse response;
        status = rustbgpd_injection_stub->AddLeasedPath(&context, request, &response);

        if (status.ok()) {
            outcome = response.result().outcome();

            const auto& generation = response.generation();

            if (rustbgpd_lease_generation_known && (generation.incarnation() != rustbgpd_lease_generation.incarnation() ||
                                                    generation.sequence() != rustbgpd_lease_generation.sequence())) {
                // Our previous lease expired or rustbgpd restarted. Routes added under it may be gone
                logger << log4cpp::Priority::WARN << "rustbgpd started new lease for owner "
                       << fastnetmon_global_configuration.rustbgpd_lease_owner << ", will announce all active bans again";
                rustbgpd_reconcile_needed = true;
            }

            rustbgpd_lease_generation       = generation;
            rustbgpd_lease_generation_known = true;
        }
    } else {
        rustbgpd::v1::AddPathResponse response;
        status = rustbgpd_injection_stub->AddPath(&context, path, &response);

        if (status.ok()) {
            outcome = response.outcome();
        }
    }

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "rustbgpd rejected announce of " << route.key() << " next hop "
               << route.next_hop << ": " << rustbgpd_describe_status(status);

        if (status.error_code() == grpc::StatusCode::FAILED_PRECONDITION) {
            logger << log4cpp::Priority::ERROR << "Prefix " << route.key() << " is held in rustbgpd by another lease owner or "
                   << "without lease. Remove it with: rbgp rib delete " << route.key() << " --override-owner";
        }

        if (rustbgpd_is_transient_error(status)) {
            rustbgpd_reconcile_needed = true;
        }

        return false;
    }

    logger << log4cpp::Priority::INFO << "rustbgpd announced " << route.key() << " next hop " << route.next_hop
           << " outcome " << rustbgpd::v1::PathInjectOutcome_Name(outcome);

    return true;
}

// Must be called with rustbgpd_mutex held
bool rustbgpd_delete_route(const rustbgpd_route_t& route) {
    rustbgpd::v1::DeletePathRequest request;

    request.set_prefix(route.prefix);
    request.set_prefix_length(route.prefix_length);

    // rustbgpd may have restarted and lost this route already
    request.set_allow_missing(true);

    if (fastnetmon_global_configuration.rustbgpd_lease) {
        request.set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
    }

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    rustbgpd::v1::DeletePathResponse response;
    grpc::Status status = rustbgpd_injection_stub->DeletePath(&context, request, &response);

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "rustbgpd rejected withdrawal of " << route.key() << ": "
               << rustbgpd_describe_status(status);

        if (rustbgpd_is_transient_error(status)) {
            rustbgpd_reconcile_needed = true;
        }

        return false;
    }

    logger << log4cpp::Priority::INFO << "rustbgpd withdrew " << route.key() << " outcome "
           << rustbgpd::v1::PathDeleteOutcome_Name(response.outcome());

    return true;
}

// Announces all active bans and retries failed withdrawals. Must be called with rustbgpd_mutex held
void rustbgpd_reconcile(const std::string& reason) {
    logger << log4cpp::Priority::INFO << "rustbgpd reconcile (" << reason << "): " << rustbgpd_active_routes.size()
           << " active bans, " << rustbgpd_pending_withdrawals.size() << " pending withdrawals";

    bool transient_failure = false;
    unsigned int failed    = 0;

    for (auto it = rustbgpd_pending_withdrawals.begin(); it != rustbgpd_pending_withdrawals.end();) {
        rustbgpd_reconcile_needed = false;

        if (rustbgpd_delete_route(it->second)) {
            it = rustbgpd_pending_withdrawals.erase(it);
        } else {
            failed++;
            transient_failure = transient_failure || rustbgpd_reconcile_needed;
            ++it;
        }
    }

    for (const auto& [key, route] : rustbgpd_active_routes) {
        rustbgpd_reconcile_needed = false;

        if (!rustbgpd_add_route(route)) {
            failed++;
            transient_failure = transient_failure || rustbgpd_reconcile_needed;
        }
    }

    // Retry soon only when rustbgpd was unreachable. A new lease generation seen during this pass
    // needs no other pass as we have just announced everything
    rustbgpd_reconcile_needed = transient_failure;

    if (failed > 0) {
        logger << log4cpp::Priority::ERROR << "rustbgpd reconcile finished with " << failed << " failed calls";
    }
}

// Must be called with rustbgpd_mutex held
void rustbgpd_renew_lease() {
    rustbgpd::v1::RenewLeaseRequest request;
    request.set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
    *request.mutable_generation() = rustbgpd_lease_generation;
    request.set_lease_seconds(fastnetmon_global_configuration.rustbgpd_lease_time);

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    rustbgpd::v1::RenewLeaseResponse response;
    grpc::Status status = rustbgpd_injection_stub->RenewLease(&context, request, &response);

    if (status.ok()) {
        return;
    }

    logger << log4cpp::Priority::ERROR << "rustbgpd lease renewal for owner "
           << fastnetmon_global_configuration.rustbgpd_lease_owner << " failed: " << rustbgpd_describe_status(status);

    if (status.error_code() == grpc::StatusCode::FAILED_PRECONDITION) {
        // Lease expired or rustbgpd restarted. First leased add will start new lease
        rustbgpd_lease_generation_known = false;
        rustbgpd_reconcile_needed       = true;
    }
}

bool rustbgpd_check_liveness() {
    grpc::ClientContext context;
    rustbgpd_prepare_context(context, 1);

    // Wait for connection up to deadline instead of failing at once. Without call in progress gRPC
    // makes progress on new connections only from its backup poller every 5 seconds and we would see
    // restarted rustbgpd up to 5 seconds late
    context.set_wait_for_ready(true);

    rustbgpd::v1::CheckLivenessRequest request;
    rustbgpd::v1::CheckLivenessResponse response;

    return rustbgpd_control_stub->CheckLiveness(&context, request, &response).ok();
}

void rustbgpd_reconcile_thread() {
    using clock = std::chrono::steady_clock;

    // So that we log if rustbgpd is not reachable on start
    bool reachable = true;

    auto next_reconcile = clock::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
    auto next_renewal = clock::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time / 3);

    while (true) {
        std::this_thread::sleep_for(rustbgpd_probe_interval);

        bool alive = rustbgpd_check_liveness();

        if (!alive) {
            if (reachable) {
                logger << log4cpp::Priority::ERROR << "rustbgpd is not reachable at " << fastnetmon_global_configuration.rustbgpd_target;
            }

            reachable = false;
            continue;
        }

        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

        if (!reachable) {
            reachable = true;
            rustbgpd_reconcile("rustbgpd is reachable");
            next_reconcile = clock::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
            continue;
        }

        if (fastnetmon_global_configuration.rustbgpd_lease && rustbgpd_lease_generation_known && clock::now() >= next_renewal) {
            if (rustbgpd_active_routes.empty()) {
                // Nothing to keep, let lease expire
                rustbgpd_lease_generation_known = false;
            } else {
                rustbgpd_renew_lease();
            }

            next_renewal = clock::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time / 3);
        }

        if (rustbgpd_reconcile_needed) {
            rustbgpd_reconcile("previous calls failed");
        } else if (clock::now() >= next_reconcile) {
            rustbgpd_reconcile("periodic");
            next_reconcile = clock::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
        }
    }
}

void rustbgpd_read_bool(const std::string& name, bool& value) {
    if (configuration_map.count(name)) {
        value = configuration_map[name] == "on";
    }
}

void rustbgpd_read_string(const std::string& name, std::string& value) {
    if (configuration_map.count(name)) {
        value = configuration_map[name];
    }
}

bool rustbgpd_read_number(const std::string& name, unsigned int& value, unsigned int min, unsigned int max) {
    if (configuration_map.count(name) == 0) {
        return true;
    }

    int parsed = 0;

    if (!convert_string_to_positive_integer_safe(configuration_map[name], parsed) || parsed < int(min) || parsed > int(max)) {
        logger << log4cpp::Priority::ERROR << name << " must be a number from " << min << " to " << max << ", got "
               << configuration_map[name];
        return false;
    }

    value = parsed;
    return true;
}

bool rustbgpd_read_next_hop(const std::string& name, std::string& value, int family) {
    rustbgpd_read_string(name, value);

    unsigned char buffer[sizeof(struct in6_addr)];

    if (inet_pton(family, value.c_str(), buffer) != 1) {
        logger << log4cpp::Priority::ERROR << "Cannot parse " << name << " as IP" << (family == AF_INET ? "v4" : "v6")
               << " address: " << value;
        return false;
    }

    return true;
}

bool rustbgpd_read_community(const std::string& name, std::string& value) {
    rustbgpd_read_string(name, value);

    bgp_community_attribute_element_t community;

    if (!read_bgp_community_from_string(value, community)) {
        logger << log4cpp::Priority::ERROR << "Cannot parse " << name << " as BGP community: " << value;
        return false;
    }

    return true;
}

bool rustbgpd_target_is_local(const std::string& target) {
    return target.rfind("unix:", 0) == 0 || target.rfind("127.", 0) == 0 || target.rfind("[::1]:", 0) == 0 ||
           target.rfind("localhost:", 0) == 0;
}

bool rustbgpd_action_init() {
    logger << log4cpp::Priority::INFO << "rustbgpd action module loaded";

    auto& configuration = fastnetmon_global_configuration;

    rustbgpd_read_string("rustbgpd_target", configuration.rustbgpd_target);
    rustbgpd_read_string("rustbgpd_token_file", configuration.rustbgpd_token_file);
    rustbgpd_read_bool("rustbgpd_announce_host", configuration.rustbgpd_announce_host);
    rustbgpd_read_bool("rustbgpd_announce_whole_subnet", configuration.rustbgpd_announce_whole_subnet);
    rustbgpd_read_bool("rustbgpd_announce_host_ipv6", configuration.rustbgpd_announce_host_ipv6);
    rustbgpd_read_bool("rustbgpd_lease", configuration.rustbgpd_lease);
    rustbgpd_read_string("rustbgpd_lease_owner", configuration.rustbgpd_lease_owner);

    bool valid =
        rustbgpd_read_next_hop("rustbgpd_next_hop_host_ipv4", configuration.rustbgpd_next_hop_host_ipv4, AF_INET) &&
        rustbgpd_read_next_hop("rustbgpd_next_hop_subnet_ipv4", configuration.rustbgpd_next_hop_subnet_ipv4, AF_INET) &&
        rustbgpd_read_next_hop("rustbgpd_next_hop_host_ipv6", configuration.rustbgpd_next_hop_host_ipv6, AF_INET6) &&
        rustbgpd_read_community("rustbgpd_community_host", configuration.rustbgpd_community_host) &&
        rustbgpd_read_community("rustbgpd_community_subnet", configuration.rustbgpd_community_subnet) &&
        rustbgpd_read_community("rustbgpd_community_host_ipv6", configuration.rustbgpd_community_host_ipv6) &&
        rustbgpd_read_number("rustbgpd_reconcile_interval", configuration.rustbgpd_reconcile_interval, 1, 3600) &&
        rustbgpd_read_number("rustbgpd_lease_time", configuration.rustbgpd_lease_time, 5, 3600);

    if (!valid) {
        return false;
    }

    // rustbgpd accepts plaintext gRPC only from its owner-only Unix socket or with bearer token
    // We do not send token in plaintext anywhere but loopback
    if (!rustbgpd_target_is_local(configuration.rustbgpd_target)) {
        logger << log4cpp::Priority::ERROR << "rustbgpd_target must be unix:///path or loopback address with port, got "
               << configuration.rustbgpd_target;
        return false;
    }

    if (!configuration.rustbgpd_token_file.empty()) {
        std::ifstream token_file(configuration.rustbgpd_token_file);

        if (!token_file.is_open() || !std::getline(token_file, rustbgpd_token)) {
            logger << log4cpp::Priority::ERROR << "Cannot read token from rustbgpd_token_file " << configuration.rustbgpd_token_file;
            return false;
        }

        boost::algorithm::trim(rustbgpd_token);

        if (rustbgpd_token.empty()) {
            logger << log4cpp::Priority::ERROR << "rustbgpd_token_file " << configuration.rustbgpd_token_file << " is empty";
            return false;
        }
    }

    if (configuration.rustbgpd_lease) {
        logger << log4cpp::Priority::WARN << "rustbgpd leases are enabled. Lease API is not part of rustbgpd's stable v1 API "
               << "and may change in future rustbgpd releases";
    }

    grpc::ChannelArguments channel_arguments;

    // Otherwise gRPC sends socket path as HTTP/2 authority and rustbgpd resets such streams
    if (configuration.rustbgpd_target.rfind("unix:", 0) == 0) {
        channel_arguments.SetString(GRPC_ARG_DEFAULT_AUTHORITY, "localhost");
    }

    // Reconnect quickly after rustbgpd restart. Default reconnect backoff grows up to 120 seconds
    // Retrying connection to absent Unix socket or closed loopback port is cheap
    // We keep default minimum connect timeout (GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, 20 seconds) as it also limits time
    // for HTTP/2 handshake
    channel_arguments.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, 250);
    channel_arguments.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, 250);

    auto channel = grpc::CreateCustomChannel(configuration.rustbgpd_target, grpc::InsecureChannelCredentials(), channel_arguments);

    rustbgpd_injection_stub = rustbgpd::v1::InjectionService::NewStub(channel);
    rustbgpd_control_stub   = rustbgpd::v1::ControlService::NewStub(channel);

    std::thread(rustbgpd_reconcile_thread).detach();

    logger << log4cpp::Priority::INFO << "rustbgpd action will use " << configuration.rustbgpd_target;

    return true;
}

rustbgpd_route_t
rustbgpd_build_route(const std::string& prefix, uint32_t prefix_length, const std::string& next_hop, const std::string& community_as_string) {
    rustbgpd_route_t route;

    route.prefix        = prefix;
    route.prefix_length = prefix_length;
    route.next_hop      = next_hop;

    // We validated it on start
    bgp_community_attribute_element_t community;

    if (read_bgp_community_from_string(community_as_string, community)) {
        route.communities.push_back(uint32_t(community.asn_number) << 16 | community.community_number);
    }

    return route;
}

void rustbgpd_ban_manage(const std::string& action,
                         bool ipv6,
                         uint32_t client_ip,
                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                         const attack_details_t& current_attack) {
    const auto& configuration = fastnetmon_global_configuration;

    std::vector<rustbgpd_route_t> routes;

    if (ipv6) {
        if (configuration.rustbgpd_announce_host_ipv6) {
            char address[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &client_ipv6.subnet_address, address, sizeof(address));

            routes.push_back(rustbgpd_build_route(address, 128, configuration.rustbgpd_next_hop_host_ipv6,
                                                  configuration.rustbgpd_community_host_ipv6));
        }
    } else {
        if (configuration.rustbgpd_announce_whole_subnet) {
            routes.push_back(rustbgpd_build_route(convert_ip_as_uint_to_string(current_attack.customer_network.subnet_address),
                                                  current_attack.customer_network.cidr_prefix_length, configuration.rustbgpd_next_hop_subnet_ipv4,
                                                  configuration.rustbgpd_community_subnet));
        }

        if (configuration.rustbgpd_announce_host) {
            routes.push_back(rustbgpd_build_route(convert_ip_as_uint_to_string(client_ip), 32, configuration.rustbgpd_next_hop_host_ipv4,
                                                  configuration.rustbgpd_community_host));
        }
    }

    std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

    for (const auto& route : routes) {
        if (action == "ban") {
            rustbgpd_pending_withdrawals.erase(route.key());
            rustbgpd_active_routes[route.key()] = route;

            // On failure route stays in active list and reconcile will announce it
            rustbgpd_add_route(route);
        } else {
            rustbgpd_active_routes.erase(route.key());
            rustbgpd_pending_withdrawals[route.key()] = route;

            if (rustbgpd_delete_route(route)) {
                rustbgpd_pending_withdrawals.erase(route.key());
            }
        }
    }
}
