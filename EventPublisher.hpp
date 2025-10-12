#pragma once

#include <vector>
#include <mutex>
#include "msg.hpp"
#include "Observer.hpp"

class EventPublisher
{
private:
	std::vector<Observer*> observers;
	std::mutex mut;

public:
	void detach(Observer* obs);
	void attach(Observer* obs);
	void notify(const DebugEvent& de);

};