#include "vpn/mesh/kademlia.hpp"
#include <algorithm>
#include <random>
#include <cstring>

namespace vpn::mesh {

// --- KBucket ---

bool KBucket::add_or_update(const KBucketEntry& entry) {
    // Check if node already exists
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->node_id == entry.node_id) {
            // Move to tail (most recently seen)
            auto updated = *it;
            updated.info = entry.info;
            updated.last_seen = std::chrono::steady_clock::now();
            updated.is_stale = false;
            entries_.erase(it);
            entries_.push_back(updated);
            last_updated_ = std::chrono::steady_clock::now();
            return true;
        }
    }

    // Not in bucket - add if space available
    if (!is_full()) {
        entries_.push_back(entry);
        last_updated_ = std::chrono::steady_clock::now();
        return true;
    }

    // Bucket full - caller should ping head node first
    return false;
}

void KBucket::remove(const NodeId& node_id) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
            [&node_id](const auto& e) { return e.node_id == node_id; }),
        entries_.end()
    );
}

void KBucket::evict_head(const NodeId& replacement_id, const NodeInfo& replacement_info) {
    if (entries_.empty()) return;
    entries_.pop_front();

    KBucketEntry entry;
    entry.node_id = replacement_id;
    entry.info = replacement_info;
    entry.last_seen = std::chrono::steady_clock::now();
    entries_.push_back(entry);
    last_updated_ = std::chrono::steady_clock::now();
}

const KBucketEntry* KBucket::head() const {
    if (entries_.empty()) return nullptr;
    return &entries_.front();
}

bool KBucket::needs_refresh(std::chrono::minutes interval) const {
    auto elapsed = std::chrono::steady_clock::now() - last_updated_;
    return elapsed >= interval;
}

const KBucketEntry* KBucket::find(const NodeId& node_id) const {
    for (const auto& entry : entries_) {
        if (entry.node_id == node_id) {
            return &entry;
        }
    }
    return nullptr;
}

// --- RoutingTable ---

RoutingTable::RoutingTable(const NodeId& local_id)
    : local_id_(local_id) {}

bool RoutingTable::add_or_update(const NodeInfo& info) {
    if (info.node_id == local_id_) return false;  // Don't add ourselves

    int idx = bucket_index(info.node_id);
    if (idx < 0) return false;

    KBucketEntry entry;
    entry.node_id = info.node_id;
    entry.info = info;
    entry.last_seen = std::chrono::steady_clock::now();

    return buckets_[idx].add_or_update(entry);
}

void RoutingTable::remove(const NodeId& node_id) {
    int idx = bucket_index(node_id);
    if (idx >= 0) {
        buckets_[idx].remove(node_id);
    }
}

std::vector<NodeInfo> RoutingTable::find_closest(const NodeId& target, size_t count) const {
    struct DistEntry {
        NodeId distance;
        const NodeInfo* info;
    };

    std::vector<DistEntry> candidates;

    for (const auto& bucket : buckets_) {
        for (const auto& entry : bucket.entries()) {
            candidates.push_back({
                xor_distance(target, entry.node_id),
                &entry.info
            });
        }
    }

    // Sort by XOR distance
    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) { return a.distance < b.distance; });

    std::vector<NodeInfo> result;
    size_t n = std::min(count, candidates.size());
    result.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        result.push_back(*candidates[i].info);
    }

    return result;
}

int RoutingTable::bucket_index(const NodeId& node_id) const {
    auto dist = xor_distance(local_id_, node_id);
    int bit = highest_bit(dist);
    if (bit < 0) return -1;  // Same as local ID
    return bit;
}

std::vector<NodeInfo> RoutingTable::all_nodes() const {
    std::vector<NodeInfo> result;
    for (const auto& bucket : buckets_) {
        for (const auto& entry : bucket.entries()) {
            result.push_back(entry.info);
        }
    }
    return result;
}

size_t RoutingTable::node_count() const {
    size_t count = 0;
    for (const auto& bucket : buckets_) {
        count += bucket.size();
    }
    return count;
}

std::vector<int> RoutingTable::stale_buckets(std::chrono::minutes interval) const {
    std::vector<int> result;
    for (int i = 0; i < static_cast<int>(NODE_ID_BITS); ++i) {
        if (!buckets_[i].is_empty() && buckets_[i].needs_refresh(interval)) {
            result.push_back(i);
        }
    }
    return result;
}

NodeId RoutingTable::random_id_in_bucket(const NodeId& local_id, int bucket_idx) {
    // bucket_idx is the position returned by highest_bit(xor_distance(local, remote)).
    // highest_bit returns: (NODE_ID_BITS - 1) - (byte_idx * 8 + (7 - bit_in_byte))
    // So bucket_idx=0 means only the very last bit (byte 19, bit 0) differs.
    // bucket_idx=159 means byte 0, bit 7 differs (the most significant bit).
    //
    // We need to construct a result such that xor_distance(local_id, result)
    // has exactly bit bucket_idx as its highest set bit.

    // Convert bucket_idx to byte/bit position in the XOR distance
    // highest_bit maps: for byte i, bit b (7=MSB, 0=LSB):
    //   highest_bit = (NODE_ID_BITS - 1) - (i * 8 + (7 - b))
    // Solving for i, b given bucket_idx:
    //   i * 8 + (7 - b) = (NODE_ID_BITS - 1) - bucket_idx
    int distance_from_msb = (NODE_ID_BITS - 1) - bucket_idx;
    int target_byte = distance_from_msb / 8;
    int target_bit = 7 - (distance_from_msb % 8);  // bit within byte (7=MSB, 0=LSB)

    // Start with local_id (XOR distance = 0)
    NodeId result = local_id;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    // Set the target bit to differ (flip it in result so XOR has it set)
    result[target_byte] ^= static_cast<uint8_t>(1 << target_bit);

    // Randomize all lower bits (bits below target_bit in target_byte, and all subsequent bytes)
    // Lower bits within the target byte
    for (int b = 0; b < target_bit; ++b) {
        if (dist(gen) & 1) {
            result[target_byte] ^= static_cast<uint8_t>(1 << b);
        }
    }

    // All subsequent bytes are random (XOR distance bits below the target)
    for (int i = target_byte + 1; i < static_cast<int>(NODE_ID_SIZE); ++i) {
        result[i] = local_id[i] ^ dist(gen);
    }

    return result;
}

// --- DhtStore ---

void DhtStore::store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value,
                     const NodeId& publisher, uint32_t ttl_seconds) {
    std::lock_guard lock(mutex_);
    auto k = key_to_string(key);
    store_[k] = StoreEntry{
        value,
        std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds),
        publisher
    };
}

std::optional<std::vector<uint8_t>> DhtStore::find(const std::vector<uint8_t>& key) const {
    std::lock_guard lock(mutex_);
    auto it = store_.find(key_to_string(key));
    if (it == store_.end()) return std::nullopt;
    if (it->second.expires_at < std::chrono::steady_clock::now()) return std::nullopt;
    return it->second.value;
}

void DhtStore::expire() {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = store_.begin(); it != store_.end(); ) {
        if (it->second.expires_at < now) {
            it = store_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<std::pair<std::vector<uint8_t>, DhtStore::StoreEntry>> DhtStore::all_entries() const {
    std::lock_guard lock(mutex_);
    std::vector<std::pair<std::vector<uint8_t>, StoreEntry>> result;
    auto now = std::chrono::steady_clock::now();
    for (const auto& [key_str, entry] : store_) {
        if (entry.expires_at >= now) {
            // Convert key string back to bytes
            std::vector<uint8_t> key(key_str.begin(), key_str.end());
            result.push_back({key, entry});
        }
    }
    return result;
}

size_t DhtStore::size() const {
    std::lock_guard lock(mutex_);
    return store_.size();
}

std::string DhtStore::key_to_string(const std::vector<uint8_t>& key) {
    return std::string(key.begin(), key.end());
}

// --- IterativeLookup ---

IterativeLookup::IterativeLookup(const NodeId& target,
                                   const std::vector<NodeInfo>& initial_nodes,
                                   size_t k, size_t alpha)
    : target_(target), k_(k), alpha_(alpha) {
    for (const auto& node : initial_nodes) {
        LookupEntry entry;
        entry.info = node;
        entry.distance = xor_distance(target_, node.node_id);
        entries_.push_back(entry);
    }

    // Sort by distance
    std::sort(entries_.begin(), entries_.end(),
        [](const auto& a, const auto& b) { return a.distance < b.distance; });
}

std::vector<NodeInfo> IterativeLookup::next_to_query() {
    if (state_ != State::Running) return {};

    std::vector<NodeInfo> to_query;
    for (auto& entry : entries_) {
        if (!entry.queried && !entry.failed && to_query.size() < alpha_) {
            entry.queried = true;
            pending_queries_++;
            to_query.push_back(entry.info);
        }
    }

    if (to_query.empty() && pending_queries_ == 0) {
        update_state();
    }

    return to_query;
}

void IterativeLookup::process_response(const NodeId& responder,
                                         const std::vector<NodeInfo>& closer_nodes) {
    // Mark responder as responded
    for (auto& entry : entries_) {
        if (entry.info.node_id == responder && entry.queried && !entry.responded) {
            entry.responded = true;
            if (pending_queries_ > 0) pending_queries_--;
            break;
        }
    }

    // Add new nodes
    bool added_new = false;
    for (const auto& node : closer_nodes) {
        bool already_exists = false;
        for (const auto& entry : entries_) {
            if (entry.info.node_id == node.node_id) {
                already_exists = true;
                break;
            }
        }

        if (!already_exists) {
            LookupEntry new_entry;
            new_entry.info = node;
            new_entry.distance = xor_distance(target_, node.node_id);
            entries_.push_back(new_entry);
            added_new = true;
        }
    }

    if (added_new) {
        // Re-sort by distance
        std::sort(entries_.begin(), entries_.end(),
            [](const auto& a, const auto& b) { return a.distance < b.distance; });
    }

    update_state();
}

void IterativeLookup::mark_failed(const NodeId& node_id) {
    for (auto& entry : entries_) {
        if (entry.info.node_id == node_id && entry.queried && !entry.responded) {
            entry.failed = true;
            if (pending_queries_ > 0) pending_queries_--;
            break;
        }
    }
    update_state();
}

std::vector<NodeInfo> IterativeLookup::closest_results() const {
    std::vector<NodeInfo> result;
    // Return k closest nodes, preferring those that responded
    for (const auto& entry : entries_) {
        if (!entry.failed) {
            result.push_back(entry.info);
            if (result.size() >= k_) break;
        }
    }
    // If we have no non-failed results, return all entries sorted by distance
    if (result.empty()) {
        for (const auto& entry : entries_) {
            result.push_back(entry.info);
            if (result.size() >= k_) break;
        }
    }
    return result;
}

void IterativeLookup::update_state() {
    if (pending_queries_ > 0) return;

    // Check if there are still unqueried nodes closer than our current k-th
    bool has_unqueried = false;
    size_t checked = 0;
    for (const auto& entry : entries_) {
        if (checked >= k_) break;
        if (!entry.queried && !entry.failed) {
            has_unqueried = true;
            break;
        }
        checked++;
    }

    if (!has_unqueried && pending_queries_ == 0) {
        state_ = State::Converged;
    }
}

} // namespace vpn::mesh
