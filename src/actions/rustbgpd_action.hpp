#pragma once

#include "../fastnetmon_types.hpp"

#include "../attack_details.hpp"

#include <string>

bool rustbgpd_action_init();

// Stops worker thread. Safe to call more than once
void rustbgpd_action_shutdown();

// Only changes desired state, gRPC calls are made by worker thread. Call it in order of ban and unban events
void rustbgpd_ban_manage(const std::string& action,
                         bool ipv6,
                         uint32_t client_ip,
                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                         const attack_details_t& current_attack);
