#pragma once

#include "../fastnetmon_types.hpp"

#include "../attack_details.hpp"

#include <string>

#include <sys/stat.h>

bool rustbgpd_action_init();

// Stops worker thread. Safe to call more than once
void rustbgpd_action_shutdown();

// Stops worker from signal handler: only async-signal-safe operations, never locks or joins.
// Waits up to call deadline for worker to finish. rustbgpd_action_shutdown does nothing after it
void rustbgpd_action_signal_shutdown();

// Only changes desired state, gRPC calls are made by worker thread. Call it in order of ban and unban events
void rustbgpd_ban_manage(const std::string& action,
                         bool ipv6,
                         uint32_t client_ip,
                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                         const attack_details_t& current_attack);

// Decides whether metadata of rustbgpd_token_file allows us to use it: regular file owned by effective_uid or root,
// no access for group or others. Returns empty string or reason to reject it
std::string rustbgpd_check_token_file_metadata(const struct stat& file_stat, uid_t effective_uid);
