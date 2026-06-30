#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

class PacketView
{
public:
    PacketView(const std::vector<uint8_t>& bytes, size_t offset = 0, size_t length = static_cast<size_t>(-1))
        : bytes_(bytes), begin_(offset)
    {
        if(offset > bytes.size())
        {
            begin_ = bytes.size();
        }
        const size_t available = bytes.size() - begin_;
        size_ = length > available ? available : length;
    }

    size_t size() const { return size_; }
    bool contains(size_t offset, size_t length = 1) const
    {
        return offset <= size_ && length <= size_ - offset;
    }

    bool u8(size_t offset, uint8_t& value) const
    {
        if(!contains(offset)) return false;
        value = bytes_[begin_ + offset];
        return true;
    }

    bool be16(size_t offset, uint16_t& value) const
    {
        if(!contains(offset, 2)) return false;
        value = static_cast<uint16_t>((static_cast<uint16_t>(bytes_[begin_ + offset]) << 8) |
                                      bytes_[begin_ + offset + 1]);
        return true;
    }

    bool be24(size_t offset, uint32_t& value) const
    {
        if(!contains(offset, 3)) return false;
        value = (static_cast<uint32_t>(bytes_[begin_ + offset]) << 16) |
                (static_cast<uint32_t>(bytes_[begin_ + offset + 1]) << 8) |
                 static_cast<uint32_t>(bytes_[begin_ + offset + 2]);
        return true;
    }

    bool be32(size_t offset, uint32_t& value) const
    {
        if(!contains(offset, 4)) return false;
        value = (static_cast<uint32_t>(bytes_[begin_ + offset]) << 24) |
                (static_cast<uint32_t>(bytes_[begin_ + offset + 1]) << 16) |
                (static_cast<uint32_t>(bytes_[begin_ + offset + 2]) << 8) |
                 static_cast<uint32_t>(bytes_[begin_ + offset + 3]);
        return true;
    }

    std::vector<uint8_t> copy(size_t offset, size_t length) const
    {
        if(!contains(offset, length)) return {};
        const auto first = bytes_.begin() + static_cast<std::ptrdiff_t>(begin_ + offset);
        return std::vector<uint8_t>(first, first + static_cast<std::ptrdiff_t>(length));
    }

private:
    const std::vector<uint8_t>& bytes_;
    size_t begin_ = 0;
    size_t size_ = 0;
};
