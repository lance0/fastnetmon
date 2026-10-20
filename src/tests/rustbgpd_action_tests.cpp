// Tests for rustbgpd action against in-process mock of rustbgpd's gRPC API
//
// cmake -DBUILD_TESTS=ON .. && make rustbgpd_action_tests && ./rustbgpd_action_tests

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "log4cpp/Category.hh"
#include "log4cpp/LayoutAppender.hh"
#include "log4cpp/Priority.hh"

#include "../actions/rustbgpd_action.hpp"
#include "../fastnetmon_configuration_scheme.hpp"
#include "../rustbgpd_client/rustbgpd_injection.grpc.pb.h"

log4cpp::Category& logger = log4cpp::Category::getRoot();
std::map<std::string, std::string> configuration_map;
fastnetmon_configuration_t fastnetmon_global_configuration;

using namespace std::chrono_literals;

// Keeps all log messages so tests can check them
class captured_log_t : public log4cpp::LayoutAppender {
    public:
    captured_log_t() : log4cpp::LayoutAppender("captured") {
    }

    void close() override {
    }

    std::string text() {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return buffer;
    }

    void clear() {
        std::lock_guard<std::mutex> lock_guard(mutex);
        buffer.clear();
    }

    // Raise this signal from inside logging of ban request. Action logs it while it holds its lock
    std::atomic<int> raise_on_ban_request{ 0 };

    protected:
    void _append(const log4cpp::LoggingEvent& event) override {
        {
            std::lock_guard<std::mutex> lock_guard(mutex);
            buffer += event.message + "\n";
        }

        int signal_number = raise_on_ban_request.exchange(0);

        if (signal_number != 0 && event.message.find("requested by ban") != std::string::npos) {
            raise(signal_number);
        } else if (signal_number != 0) {
            raise_on_ban_request = signal_number;
        }
    }

    private:
    std::mutex mutex;
    std::string buffer;
};

captured_log_t* captured_log = nullptr;

// State of mock rustbgpd and knobs which change its behaviour
class mock_state_t {
    public:
    std::mutex mutex;
    std::map<std::string, rustbgpd::v1::AddPathRequest> routes;
    std::map<std::string, std::string> owners;

    std::atomic<int> adds_started{ 0 };
    std::atomic<int> deletes{ 0 };
    std::atomic<int> renewals{ 0 };

    std::atomic<int> add_delay_ms{ 0 };

    // Announces wait while it is set
    std::atomic<bool> hold_adds{ false };

    // Answer next announce without outcome
    std::atomic<bool> omit_next_add_outcome{ false };

    // Answer OK without outcome
    std::atomic<bool> omit_outcome{ false };

    // Answer leased add without generation
    std::atomic<bool> omit_generation{ false };

    // After answering next leased add, expire lease: drop owner's routes and start new generation on next add
    std::atomic<bool> expire_after_next_add{ false };

    std::atomic<int> liveness_code{ grpc::StatusCode::OK };

    bool lease_live      = false;
    uint64_t incarnation = 7;
    uint64_t sequence    = 1;

    std::string last_authorization;

    bool has(const std::string& key) {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return routes.count(key) > 0;
    }
};

std::string route_key(const std::string& prefix, uint32_t length) {
    return prefix + "/" + std::to_string(length);
}

class mock_injection_t final : public rustbgpd::v1::InjectionService::Service {
    public:
    explicit mock_injection_t(mock_state_t& state) : state(state) {
    }

    grpc::Status AddPath(grpc::ServerContext* context,
                         const rustbgpd::v1::AddPathRequest* request,
                         rustbgpd::v1::AddPathResponse* response) override {
        auto outcome = add(context, *request, "");
        set_outcome(response, outcome);
        return grpc::Status::OK;
    }

    grpc::Status AddLeasedPath(grpc::ServerContext* context,
                               const rustbgpd::v1::AddLeasedPathRequest* request,
                               rustbgpd::v1::AddLeasedPathResponse* response) override {
        auto outcome = add(context, request->path(), request->lease().owner());
        set_outcome(response->mutable_result(), outcome);

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        if (!state.lease_live) {
            state.lease_live = true;
            state.sequence++;
        }

        if (!state.omit_generation) {
            response->mutable_generation()->set_incarnation(state.incarnation);
            response->mutable_generation()->set_sequence(state.sequence);
        }

        if (state.expire_after_next_add.exchange(false)) {
            for (auto it = state.routes.begin(); it != state.routes.end();) {
                if (state.owners[it->first] == request->lease().owner()) {
                    it = state.routes.erase(it);
                } else {
                    ++it;
                }
            }

            state.lease_live = false;
        }

        return grpc::Status::OK;
    }

    grpc::Status DeletePath(grpc::ServerContext* context,
                            const rustbgpd::v1::DeletePathRequest* request,
                            rustbgpd::v1::DeletePathResponse* response) override {
        state.deletes++;

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        if (state.routes.erase(route_key(request->prefix(), request->prefix_length())) > 0) {
            response->set_outcome(rustbgpd::v1::PATH_DELETE_OUTCOME_DELETED);
        } else if (request->allow_missing()) {
            response->set_outcome(rustbgpd::v1::PATH_DELETE_OUTCOME_NOT_PRESENT);
        } else {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "no such route");
        }

        if (state.omit_outcome) {
            response->clear_outcome();
        }

        return grpc::Status::OK;
    }

    grpc::Status RenewLease(grpc::ServerContext* context,
                            const rustbgpd::v1::RenewLeaseRequest* request,
                            rustbgpd::v1::RenewLeaseResponse* response) override {
        state.renewals++;

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        if (!state.lease_live || request->generation().incarnation() != state.incarnation ||
            request->generation().sequence() != state.sequence) {
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "not the live lease");
        }

        *response->mutable_generation() = request->generation();
        return grpc::Status::OK;
    }

    private:
    rustbgpd::v1::PathInjectOutcome
    add(grpc::ServerContext* context, const rustbgpd::v1::AddPathRequest& request, const std::string& owner) {
        state.adds_started++;

        std::this_thread::sleep_for(std::chrono::milliseconds(state.add_delay_ms.load()));

        while (state.hold_adds) {
            std::this_thread::sleep_for(5ms);
        }

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        auto authorization = context->client_metadata().find("authorization");

        if (authorization != context->client_metadata().end()) {
            state.last_authorization = std::string(authorization->second.data(), authorization->second.size());
        }

        auto key     = route_key(request.prefix(), request.prefix_length());
        bool existed = state.routes.count(key) > 0;

        state.routes[key] = request;
        state.owners[key] = owner;

        return existed ? rustbgpd::v1::PATH_INJECT_OUTCOME_UNCHANGED : rustbgpd::v1::PATH_INJECT_OUTCOME_CREATED;
    }

    void set_outcome(rustbgpd::v1::AddPathResponse* response, rustbgpd::v1::PathInjectOutcome outcome) {
        if (!state.omit_outcome && !state.omit_next_add_outcome.exchange(false)) {
            response->set_outcome(outcome);
        }
    }

    mock_state_t& state;
};

class mock_control_t final : public rustbgpd::v1::ControlService::Service {
    public:
    explicit mock_control_t(mock_state_t& state) : state(state) {
    }

    grpc::Status CheckLiveness(grpc::ServerContext* context,
                               const rustbgpd::v1::CheckLivenessRequest* request,
                               rustbgpd::v1::CheckLivenessResponse* response) override {
        int code = state.liveness_code;

        if (code != grpc::StatusCode::OK) {
            return grpc::Status(grpc::StatusCode(code), "mock liveness failure");
        }

        return grpc::Status::OK;
    }

    private:
    mock_state_t& state;
};

bool wait_for(std::function<bool()> condition, std::chrono::milliseconds limit) {
    auto deadline = std::chrono::steady_clock::now() + limit;

    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) {
            return true;
        }

        std::this_thread::sleep_for(20ms);
    }

    return condition();
}

class RustbgpdActionTest : public ::testing::Test {
    protected:
    void SetUp() override {
        char directory_template[] = "/tmp/rustbgpd_action_tests.XXXXXX";
        directory                 = mkdtemp(directory_template);
        socket_path               = directory + "/grpc.sock";

        injection = std::make_unique<mock_injection_t>(state);
        control   = std::make_unique<mock_control_t>(state);

        grpc::ServerBuilder builder;
        builder.AddListeningPort("unix://" + socket_path, grpc::InsecureServerCredentials());
        builder.RegisterService(injection.get());
        builder.RegisterService(control.get());
        server = builder.BuildAndStart();
        ASSERT_TRUE(server);

        configuration_map.clear();
        fastnetmon_global_configuration = fastnetmon_configuration_t{};

        configuration_map["rustbgpd_target"]             = "unix://" + socket_path;
        configuration_map["rustbgpd_reconcile_interval"] = "30";

        captured_log->clear();
    }

    void TearDown() override {
        rustbgpd_action_shutdown();
        server->Shutdown(std::chrono::system_clock::now() + 1s);
        std::filesystem::remove_all(directory);
    }

    void ipv4_action(const std::string& action, const std::string& host) {
        attack_details_t attack;
        attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

        rustbgpd_ban_manage(action, false, inet_addr(host.c_str()), subnet_ipv6_cidr_mask_t{}, attack);
    }

    std::string write_file(const std::string& name, const std::string& content, mode_t mode) {
        auto path = directory + "/" + name;
        std::ofstream(path) << content;
        chmod(path.c_str(), mode);
        return path;
    }

    mock_state_t state;
    std::unique_ptr<mock_injection_t> injection;
    std::unique_ptr<mock_control_t> control;
    std::unique_ptr<grpc::Server> server;
    std::string directory;
    std::string socket_path;
};

TEST_F(RustbgpdActionTest, announces_and_withdraws_host) {
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    {
        std::lock_guard<std::mutex> lock_guard(state.mutex);
        const auto& route = state.routes["203.0.113.7/32"];

        EXPECT_EQ(route.next_hop(), "0.0.0.0");
        EXPECT_EQ(route.origin(), 2u);
        ASSERT_EQ(route.communities_size(), 1);
        EXPECT_EQ(route.communities(0), 65535u << 16 | 666u);
    }

    ipv4_action("unban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 3s));
    EXPECT_TRUE(
        wait_for([&] { return captured_log->text().find("outcome PATH_DELETE_OUTCOME_DELETED") != std::string::npos; }, 1s));
}

// Unban which arrives while announce is still in flight must win and must not wait for it
TEST_F(RustbgpdActionTest, unban_during_slow_announce_withdraws) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_delay_ms = 1000;

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    auto started = std::chrono::steady_clock::now();
    ipv4_action("unban", "203.0.113.7");
    EXPECT_LT(std::chrono::steady_clock::now() - started, 200ms) << "unban waited for announce in flight";

    // Announce lands first, then withdrawal must follow
    EXPECT_TRUE(wait_for([&] { return state.deletes >= 1 && !state.has("203.0.113.7/32"); }, 4s));

    std::this_thread::sleep_for(1500ms);
    EXPECT_FALSE(state.has("203.0.113.7/32")) << "route came back after unban";
}

// Failed answer for announce which is already outdated must not delay withdrawal which replaced it
TEST_F(RustbgpdActionTest, failed_outdated_announce_does_not_delay_withdrawal) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.hold_adds = true;
    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    // Unban while announce is in flight, then announce gets answer which action does not accept
    ipv4_action("unban", "203.0.113.7");
    state.omit_next_add_outcome = true;
    state.hold_adds             = false;

    EXPECT_TRUE(wait_for([&] { return state.deletes >= 1 && !state.has("203.0.113.7/32"); }, 2s))
        << "withdrawal waited for retry delay of outdated announce";
}

// Shutdown cancels call in flight, joins worker and no calls happen after it
TEST_F(RustbgpdActionTest, shutdown_stops_worker_during_call) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_delay_ms = 3000;

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    auto started = std::chrono::steady_clock::now();
    rustbgpd_action_shutdown();
    EXPECT_LT(std::chrono::steady_clock::now() - started, 1500ms) << "shutdown waited for call in flight";

    int adds = state.adds_started;
    ipv4_action("ban", "203.0.113.8");
    std::this_thread::sleep_for(1500ms);
    EXPECT_EQ(state.adds_started, adds) << "worker made calls after shutdown";

    // Second call is harmless
    rustbgpd_action_shutdown();
}

// FastNetMon exits with exit() from several places. Worker must be stopped before global variables go away
TEST_F(RustbgpdActionTest, exit_without_shutdown_is_clean) {
    EXPECT_EXIT(
        {
            if (!rustbgpd_action_init()) {
                exit(2);
            }

            state.add_delay_ms = 2000;
            ipv4_action("ban", "203.0.113.7");
            wait_for([&] { return state.adds_started == 1; }, 3s);
            exit(0);
        },
        ::testing::ExitedWithCode(0), "");
}

// Thread id of action's worker thread, 0 if there is no such thread
pid_t find_worker_thread() {
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task")) {
        std::ifstream comm(entry.path() / "comm");
        std::string name;

        if (std::getline(comm, name) && name == "rustbgpd") {
            return std::stoi(entry.path().filename());
        }
    }

    return 0;
}

std::atomic<pid_t> worker_thread_id{ 0 };

// Same steps as FastNetMon's interruption_signal_handler, and tells which thread it ran on
void test_signal_handler(int signal_number) {
    rustbgpd_action_signal_shutdown();
    exit(syscall(SYS_gettid) == worker_thread_id ? 3 : 0);
}

// Signal sent to worker thread must not run handler there: handler would wait for or join the thread it runs on
TEST_F(RustbgpdActionTest, signal_is_never_handled_on_worker_thread) {
    EXPECT_EXIT(
        {
            // Hang is failure too
            alarm(20);
            signal(SIGUSR1, test_signal_handler);

            if (!rustbgpd_action_init()) {
                exit(2);
            }

            ipv4_action("ban", "203.0.113.7");
            wait_for([&] { return state.has("203.0.113.7/32"); }, 3s);

            worker_thread_id = find_worker_thread();

            if (worker_thread_id == 0) {
                exit(4);
            }

            syscall(SYS_tgkill, getpid(), worker_thread_id.load(), SIGUSR1);
            std::this_thread::sleep_for(1s);

            // Worker keeps it pending, so this thread handles it
            raise(SIGUSR1);
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        ::testing::ExitedWithCode(0), "");
}

// Like test_signal_handler, but runs action's atexit function itself and leaves with _exit: our signal is raised
// inside log4cpp, which still holds its own lock, and log4cpp's teardown in exit() would wait for it
void test_signal_handler_inside_logging(int signal_number) {
    rustbgpd_action_signal_shutdown();
    rustbgpd_action_shutdown();
    _exit(0);
}

// Signal handler runs on thread which holds action's lock: shutdown from handler must not lock it again
TEST_F(RustbgpdActionTest, signal_while_lock_is_held_does_not_deadlock) {
    EXPECT_EXIT(
        {
            alarm(20);
            signal(SIGUSR1, test_signal_handler_inside_logging);

            if (!rustbgpd_action_init()) {
                exit(2);
            }

            captured_log->raise_on_ban_request = SIGUSR1;
            ipv4_action("ban", "203.0.113.7");
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        ::testing::ExitedWithCode(0), "");
}

// Subnet announce stays while any banned host of that subnet needs it
TEST_F(RustbgpdActionTest, subnet_withdrawn_after_last_host) {
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for(
        [&] { return state.has("203.0.113.0/24") && state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s));

    ipv4_action("unban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 3s));
    std::this_thread::sleep_for(1s);
    EXPECT_TRUE(state.has("203.0.113.0/24")) << "subnet withdrawn while 203.0.113.8 is still banned";

    ipv4_action("unban", "203.0.113.8");
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.0/24") && !state.has("203.0.113.8/32"); }, 3s));
}

// Lease expires in the middle of full pass: routes added before we saw new generation must be added again
TEST_F(RustbgpdActionTest, lease_generation_change_during_pass_reannounces) {
    configuration_map["rustbgpd_lease"]      = "on";
    configuration_map["rustbgpd_lease_time"] = "60";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s));

    // Force full pass: liveness probe fails and recovers. First add of the pass (203.0.113.7) still gets old
    // generation and then lease expires, second add (203.0.113.8) starts new generation
    state.expire_after_next_add = true;
    state.liveness_code         = grpc::StatusCode::UNAVAILABLE;
    ASSERT_TRUE(wait_for([&] { return captured_log->text().find("did not answer liveness probe") != std::string::npos; }, 3s));
    state.liveness_code = grpc::StatusCode::OK;

    // Lease expired after the first add of the pass
    ASSERT_TRUE(wait_for([&] { return !state.expire_after_next_add; }, 3s));

    EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s))
        << "route lost with expired lease was not announced again";
}

TEST_F(RustbgpdActionTest, rejects_targets_other_than_unix_socket_and_loopback_address) {
    configuration_map["rustbgpd_token_file"] = write_file("token", "secret-token\n", 0600);

    for (std::string target :
         std::vector<std::string>{ "127.attacker.example:50051", "localhost:50051", "10.0.0.1:50051", "[::2]:50051",
                                   "[::ffff:127.0.0.1]:50051", "127.1:50051", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536",
                                   "127.0.0.1:50051x", "unix:relative/path", "dns:///127.0.0.1:50051", "" }) {
        configuration_map["rustbgpd_target"] = target;
        EXPECT_FALSE(rustbgpd_action_init()) << "accepted target " << target;
        rustbgpd_action_shutdown();
    }

    for (std::string target : std::vector<std::string>{ "127.0.0.1:50051", "127.10.20.30:1", "[::1]:50051",
                                                        "unix:///run/rustbgpd/grpc.sock", "unix:/run/rustbgpd/grpc.sock" }) {
        configuration_map["rustbgpd_target"] = target;
        EXPECT_TRUE(rustbgpd_action_init()) << "rejected target " << target;
        rustbgpd_action_shutdown();
    }
}

TEST_F(RustbgpdActionTest, tcp_target_requires_token) {
    configuration_map["rustbgpd_target"] = "127.0.0.1:50051";
    EXPECT_FALSE(rustbgpd_action_init());
}

// Loopback TCP with token: token goes in authorization header of each call
TEST_F(RustbgpdActionTest, tcp_target_sends_token) {
    int port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(injection.get());
    builder.RegisterService(control.get());

    // Services may be registered with one running server only
    server->Shutdown(std::chrono::system_clock::now() + 1s);
    server = builder.BuildAndStart();
    ASSERT_TRUE(server);
    ASSERT_GT(port, 0);

    configuration_map["rustbgpd_target"]     = "127.0.0.1:" + std::to_string(port);
    configuration_map["rustbgpd_token_file"] = write_file("token", "secret-token\n", 0600);
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    std::lock_guard<std::mutex> lock_guard(state.mutex);
    EXPECT_EQ(state.last_authorization, "Bearer secret-token");
}

TEST_F(RustbgpdActionTest, token_file_checks) {
    auto good = write_file("good", "secret-token\n", 0600);

    configuration_map["rustbgpd_token_file"] = good;
    EXPECT_TRUE(rustbgpd_action_init());
    rustbgpd_action_shutdown();

    auto link = directory + "/link";
    ASSERT_EQ(symlink(good.c_str(), link.c_str()), 0);

    auto fifo = directory + "/fifo";
    ASSERT_EQ(mkfifo(fifo.c_str(), 0600), 0);

    std::map<std::string, std::string> bad_files = {
        { "symbolic link", link },
        { "group and world readable", write_file("open", "secret-token\n", 0644) },
        { "group readable", write_file("group", "secret-token\n", 0640) },
        { "directory", directory },
        { "missing", directory + "/missing" },
        { "empty", write_file("empty", "\n", 0600) },
        { "too large", write_file("large", std::string(5000, 'a'), 0600) },
        { "space in token", write_file("space", "secret token\n", 0600) },
        { "fifo", fifo },
    };

    for (const auto& [name, path] : bad_files) {
        configuration_map["rustbgpd_token_file"] = path;

        // Opening FIFO without O_NONBLOCK waits for writer forever
        auto result = std::async(std::launch::async, [] { return rustbgpd_action_init(); });

        if (result.wait_for(2s) != std::future_status::ready) {
            ADD_FAILURE() << "token file check blocked on " << name;

            // Unblock reader
            int writer = open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
            close(writer);
        }

        EXPECT_FALSE(result.get()) << "accepted token file: " << name;
        rustbgpd_action_shutdown();
    }

    EXPECT_EQ(captured_log->text().find("secret"), std::string::npos) << "token content in log";
}

TEST_F(RustbgpdActionTest, lease_owner_checked_when_leases_enabled) {
    configuration_map["rustbgpd_lease"] = "on";

    for (std::string owner : std::vector<std::string>{ "", "bad owner", "owner/1", std::string(65, 'a'), "fnm:1" }) {
        configuration_map["rustbgpd_lease_owner"] = owner;
        EXPECT_FALSE(rustbgpd_action_init()) << "accepted owner '" << owner << "'";
        rustbgpd_action_shutdown();
    }

    for (std::string owner : std::vector<std::string>{ "fastnetmon", "pop1.fastnetmon_a-B9", std::string(64, 'a') }) {
        configuration_map["rustbgpd_lease_owner"] = owner;
        EXPECT_TRUE(rustbgpd_action_init()) << "rejected owner '" << owner << "'";
        rustbgpd_action_shutdown();
    }
}

// OK without outcome means rustbgpd older than 0.79.0 or unknown outcome: we keep retrying. Periodic pass is
// every 30 seconds here, failed call is retried in 10 seconds
TEST_F(RustbgpdActionTest, unrecognised_outcome_is_retried) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.omit_outcome = true;
    ipv4_action("ban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return state.adds_started >= 2; }, 12s)) << "announce was not retried";
    EXPECT_NE(captured_log->text().find("rustbgpd answered announce of 203.0.113.7/32 without recognised outcome (0)"),
              std::string::npos);

    state.omit_outcome = false;
    EXPECT_TRUE(
        wait_for([&] { return captured_log->text().find("outcome PATH_INJECT_OUTCOME_UNCHANGED") != std::string::npos; }, 12s));

    state.omit_outcome = true;
    ipv4_action("unban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return state.deletes >= 2; }, 12s)) << "withdrawal was not retried";
    EXPECT_NE(captured_log->text().find(
                  "rustbgpd answered withdrawal of 203.0.113.7/32 without recognised outcome (0)"),
              std::string::npos);
}

TEST_F(RustbgpdActionTest, leased_answer_without_generation_is_failure) {
    configuration_map["rustbgpd_lease"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    state.omit_generation = true;
    ipv4_action("ban", "203.0.113.7");
    EXPECT_TRUE(wait_for(
        [&] {
            return captured_log->text().find("rustbgpd answered leased announce of 203.0.113.7/32 without result or "
                                             "lease generation") != std::string::npos;
        },
        3s));
    EXPECT_EQ(captured_log->text().find("rustbgpd announced 203.0.113.7/32"), std::string::npos);
}

TEST_F(RustbgpdActionTest, liveness_failure_status_is_logged) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.liveness_code = grpc::StatusCode::UNAUTHENTICATED;
    EXPECT_TRUE(wait_for(
        [&] {
            return captured_log->text().find("did not answer liveness probe: UNAUTHENTICATED: mock liveness failure") !=
                   std::string::npos;
        },
        3s));
}

int main(int argc, char** argv) {
    captured_log = new captured_log_t;
    logger.addAppender(captured_log);
    logger.setPriority(log4cpp::Priority::INFO);

    ::testing::InitGoogleTest(&argc, argv);

    // Death tests fork, we have gRPC threads running
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    return RUN_ALL_TESTS();
}
