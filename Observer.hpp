#pragma once
#include "msg.hpp"


class Observer
{
public:
	virtual ~Observer() = default;
	virtual void update(const DebugEvent& de) = 0;
};