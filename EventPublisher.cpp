#include "EventPublisher.hpp"
#include "DebugAPI.hpp"

void EventPublisher::detach(DebugObserver* obs)
{
    std::lock_guard<std::mutex> lock(mut);
    observers.erase(
        std::remove(observers.begin(), observers.end(), obs),
        observers.end()
    );
}

void EventPublisher::attach(DebugObserver* obs)
{
    std::lock_guard<std::mutex> lock(mut);
    observers.push_back(obs);
}

void EventPublisher::notify(const DebugEvent& de)
{
    std::lock_guard<std::mutex> lock(mut);
    for (auto obs : observers)
        obs->update(de);

    notifyAllCObservers(de);
}