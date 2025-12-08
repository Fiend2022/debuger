#include "EventPublisher.hpp"
#include "DebugAPI.hpp"
#include <algorithm>

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
    obsSorted = false;
}

void EventPublisher::notify(const DebugEvent& de)
{
    std::lock_guard<std::mutex> lock(mut);
    if (!notifyAllCObservers(de))
    {
        std::stable_sort(observers.begin(), observers.end(),
            [](DebugObserver* a, DebugObserver* b) {
                return a->getPriority() > b->getPriority(); // выше приоритет Ч раньше
            });
        for (auto obs : observers)
            if (obs->update(de).handled)
                break;
    }

    
}