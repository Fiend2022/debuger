#pragma once


struct DebugEvent;
struct ObserverResult
{
	bool handled;
};
namespace ObserverPriority {
	constexpr int PLUGIN = 100;
	constexpr int CORE_HOOK = 200;
	constexpr int LOGGER = 10;
	constexpr int GUI = 0;
}
class DebugObserver
{
protected:
	size_t priority = ObserverPriority::LOGGER;
public:
	size_t getPriority() { return priority; };
	virtual ~DebugObserver() = default;
	virtual ObserverResult& update(const DebugEvent& de) = 0;
};