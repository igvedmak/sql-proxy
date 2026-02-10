#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <vector>

namespace sqlproxy {

/**
 * @brief Lock-free Multi-Producer Single-Consumer ring buffer
 *
 * Design:
 * - Fixed capacity (power-of-2 for fast modulo via bitmask)
 * - Producers: atomic fetch_add to reserve a unique slot (~50ns)
 * - Consumer: single-threaded sequential drain (no CAS needed)
 * - Overflow: drop newest entry + increment overflow counter
 *
 * Slot protocol:
 *   Each slot has an atomic "ready" flag. Producers reserve a slot
 *   via fetch_add on write_pos_, write the data, then set ready=true.
 *   The single consumer reads slots sequentially while ready==true,
 *   moves data out, then clears ready. This avoids ABA problems
 *   since the consumer processes strictly in order.
 *
 * @tparam T      Element type (must be move-constructible)
 * @tparam Capacity  Buffer size. Must be a power of 2. Default 65536.
 */
template <typename T, size_t Capacity = 65536>
class MPSCRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0,
                  "Capacity must be a power of 2");
    static_assert(Capacity > 0, "Capacity must be positive");
    static_assert(std::is_move_constructible_v<T>,
                  "T must be move-constructible");

public:
    MPSCRingBuffer() {
        // Initialize all slots as not ready
        for (size_t i = 0; i < Capacity; ++i) {
            slots_[i].ready.store(false, std::memory_order_relaxed);
        }
    }

    // Non-copyable, non-movable (contains atomics)
    MPSCRingBuffer(const MPSCRingBuffer&) = delete;
    MPSCRingBuffer& operator=(const MPSCRingBuffer&) = delete;
    MPSCRingBuffer(MPSCRingBuffer&&) = delete;
    MPSCRingBuffer& operator=(MPSCRingBuffer&&) = delete;

    /**
     * @brief Try to enqueue an item (producer, thread-safe)
     *
     * Multiple producers can call this concurrently. Each gets a unique
     * slot via atomic fetch_add. If the slot is still occupied (consumer
     * hasn't drained it yet), the item is dropped and overflow is counted.
     *
     * @param item  Item to enqueue (moved in)
     * @return true if enqueued, false if dropped (buffer full)
     */
    [[nodiscard]] bool try_push(T item) {
        // Reserve a unique slot atomically
        const size_t pos = write_pos_.fetch_add(1, std::memory_order_relaxed);
        const size_t index = pos & kMask;

        Slot& slot = slots_[index];

        // Check if slot is still occupied (consumer hasn't cleared it)
        if (slot.ready.load(std::memory_order_acquire)) {
            // Buffer is full at this slot - drop the item
            overflow_count_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Write data into the slot
        slot.data.emplace(std::move(item));

        // Publish: mark slot as ready for the consumer
        slot.ready.store(true, std::memory_order_release);

        return true;
    }

    /**
     * @brief Try to dequeue a single item (consumer only, NOT thread-safe)
     *
     * Must be called from a single consumer thread only.
     *
     * @return The item if available, std::nullopt if buffer is empty
     */
    [[nodiscard]] std::optional<T> try_pop() {
        const size_t index = read_pos_ & kMask;
        Slot& slot = slots_[index];

        // Check if the next slot has been published
        if (!slot.ready.load(std::memory_order_acquire)) {
            return std::nullopt;
        }

        // Move data out
        std::optional<T> result = std::move(slot.data);
        slot.data.reset();

        // Release the slot for producers
        slot.ready.store(false, std::memory_order_release);

        ++read_pos_;
        return result;
    }

    /**
     * @brief Drain up to max_count items into a batch (consumer only)
     *
     * Efficiently reads multiple items in sequence. Must be called
     * from the single consumer thread only.
     *
     * @param batch      Output vector to append items to
     * @param max_count  Maximum number of items to drain
     * @return Number of items actually drained
     */
    size_t drain(std::vector<T>& batch, size_t max_count) {
        size_t count = 0;

        while (count < max_count) {
            const size_t index = read_pos_ & kMask;
            Slot& slot = slots_[index];

            if (!slot.ready.load(std::memory_order_acquire)) {
                break;  // No more ready items
            }

            // Move data out into the batch
            if (slot.data.has_value()) {
                batch.emplace_back(std::move(*slot.data));
                slot.data.reset();
            }

            // Release the slot
            slot.ready.store(false, std::memory_order_release);

            ++read_pos_;
            ++count;
        }

        return count;
    }

    /**
     * @brief Get the number of items dropped due to overflow
     */
    [[nodiscard]] uint64_t overflow_count() const noexcept {
        return overflow_count_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Get approximate number of items in the buffer
     *
     * This is an approximation because write_pos_ and read_pos_
     * are read non-atomically relative to each other.
     */
    [[nodiscard]] size_t size_approx() const noexcept {
        const size_t w = write_pos_.load(std::memory_order_relaxed);
        const size_t r = read_pos_;
        return (w >= r) ? (w - r) : 0;
    }

    /**
     * @brief Check if buffer appears empty
     */
    [[nodiscard]] bool empty_approx() const noexcept {
        return size_approx() == 0;
    }

    /**
     * @brief Get buffer capacity
     */
    static constexpr size_t capacity() noexcept {
        return Capacity;
    }

private:
    static constexpr size_t kMask = Capacity - 1;

    /**
     * Slot holds one element plus an atomic ready flag.
     * Aligned to avoid false sharing between adjacent slots
     * that might be accessed by different threads.
     */
    struct alignas(64) Slot {
        std::optional<T> data;
        std::atomic<bool> ready{false};
    };

    // Separate cache lines for write_pos_ (hot for producers)
    // and read_pos_ (hot for consumer) to avoid false sharing.
    alignas(64) std::atomic<size_t> write_pos_{0};
    alignas(64) size_t read_pos_{0};  // Only accessed by consumer, no atomic needed

    alignas(64) std::atomic<uint64_t> overflow_count_{0};

    // The slot array
    std::array<Slot, Capacity> slots_;
};

} // namespace sqlproxy
