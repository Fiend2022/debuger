#pragma once

#define STB_IMAGE_IMPLEMENTATION
#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "msg.hpp"
#include <queue>
#include <string>
#include <functional>
#include <mutex>
#include <vector>
#include <Windows.h>

#include "Observer.hpp"

class GUI : public DebugObserver

{
private:
	GLFWwindow* window;
	bool showDebugger;
	bool succesInit;
	bool updateIP;
	CONTEXT context;
	DWORD_PTR currentIP = 0;
	size_t currentDataTabIndex = 0;
	char inputBuf[256] = "";
	std::vector<std::string> commandHistory;
	int historyPos = -1;
	std::vector<std::string> consoleLines;


	void addToConsole(const std::string& line);
	void addCmdToHistory(const std::string& cmd);

	void renderConsole();
	int textInputCallback(ImGuiInputTextCallbackData* data);
	void setupDebuggerStyle();
	std::string selectedProgram;
	std::function<void(const std::string&)> onProgramSelected;
	std::queue<DebugEvent> msgQueue;
	std::mutex msgMutex;
	bool openFilePicker();
	void renderToolbar();
	std::vector<DisasmLine> disasCode;
	std::vector<DataSection> dataSections;
	DataSection currentDataSection;
	std::vector<StackLine> stack;
	std::function<void(const std::string&)> commandCallback;
	void renderDisassemblyCode();
	void renderDisassemblyArea();
	void renderRegisters();
	void renderData();
	enum class Tab {
		Code,
		Data,
		Stack,
		Heap
	};
	Tab currentTab = Tab::Code;
	void renderDebugButtons();
	void renderStack();


public:
	GUI();
	~GUI();

	void update(const DebugEvent& de) override;
	bool ready() { return succesInit; };
	void run();
	void pushEvent(const DebugEvent& event);
	void setCommandCallback(std::function<void(const std::string&)> cb)
	{
		commandCallback = cb;
	}
};

