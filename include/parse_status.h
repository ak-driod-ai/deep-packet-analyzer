#pragma once

enum class ParseStatus
{
    NoMatch,
    NeedMoreData,
    Parsed,
    Malformed
};
