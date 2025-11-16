#pragma once


struct DebugEvent;

class DebugObserver
{
public:
	virtual ~DebugObserver() = default;
	virtual void update(const DebugEvent& de) = 0;
};