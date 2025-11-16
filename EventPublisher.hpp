#pragma once

#include <vector>
#include <mutex>
#include "msg.hpp"
#include "Observer.hpp"

class EventPublisher
{
private:
	std::vector<DebugObserver*> observers;
	std::mutex mut;

public:
	void detach(DebugObserver* obs);
	void attach(DebugObserver* obs);
	void notify(const DebugEvent& de);

};
