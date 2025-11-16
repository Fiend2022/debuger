#include "GUI.h"
#include <Windows.h>
#include <commdlg.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

std::string formatHex(const std::vector<uint8_t>& buf) {
    std::ostringstream oss;
    for (size_t i = 0; i < buf.size(); ++i) {
        if (i > 0) oss << " ";
        oss << std::setfill('0') << std::setw(2) << std::hex << (int)buf[i];
    }
    return oss.str();
}

std::string formatAscii(const std::vector<uint8_t>& buf) {
    std::string ascii;
    for (uint8_t b : buf) {
        ascii += (b >= 32 && b < 127) ? (char)b : '.';
    }
    return ascii;
}

GUI::GUI()
{
    if (!glfwInit()) return;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    window = glfwCreateWindow(1280, 720, "Debugger GUI", nullptr, nullptr);
    if (!window)
    {
        glfwTerminate();
        return;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // V-Sync

    // --- Инициализация OpenGL ---
    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress))
        return;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    float fontSize = 18.0f; // Хороший размер для дебаггера

    io.Fonts->Clear();

    ImFont* mainFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", fontSize);

    if (!mainFont)
        mainFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", fontSize);
    if (!mainFont)
        mainFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", fontSize);
 

    if (!mainFont)
    {
        ImFont* font = io.Fonts->Fonts[0];
        font->Scale = 1.4f;  // Увеличиваем стандартный шрифт
    }


    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();

    setupDebuggerStyle();


    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    showDebugger = true;
    succesInit = true;
}




void GUI::run()
{
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        static bool windowOpen = true;
        ImGui::SetNextWindowSize(ImVec2(1108, 563), ImGuiCond_Once);
        std::vector<DebugEvent> localEvents;
        {
            std::lock_guard<std::mutex> lock(msgMutex);
            while (!msgQueue.empty()) {
                localEvents.push_back(msgQueue.front());
                msgQueue.pop();
            }
        }

        for (const auto& ev : localEvents)
        {
            switch (ev.type)
            {
            case DebugEvent::CreateProc:
                disasCode = ev.disasmCode;
                dataSections = ev.data;
                currentDataSection = dataSections[0];
                currentIP = ev.address;
                updateIP = true;
                stack = ev.stackData;
                break;
            case DebugEvent::Step:
            case DebugEvent::HardwareBreak:
            case DebugEvent::BreakpointEvent:
            case DebugEvent::StepOver:
            case DebugEvent::StepOut:
                currentIP = ev.address;
                updateIP = true;
                context = ev.context;
                stack = ev.stackData;
                break;
            case DebugEvent::DisasmCode:
            case DebugEvent::BreakList:
            case DebugEvent::ModList:
            case DebugEvent::ThreadList:
            case DebugEvent::Nope:
            case DebugEvent::Dump:
            case DebugEvent::BreakpointSetup:
            case DebugEvent::Run:
            case DebugEvent::HardBreakpointSetup:
            case DebugEvent::SetupTrace:
            case DebugEvent::DbgError:
            case DebugEvent::DbgWarning:

                if (!ev.message.empty())
                    addToConsole(ev.message);
                break;
            default:
                break;
            }

        }
        if (ImGui::Begin("Debugger", &windowOpen))
        {
            if (selectedProgram.empty())
                renderToolbar();
            else
            {
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5, 5));
                renderDebugButtons();
                ImGui::PopStyleVar();
            }
                
            ImGui::Separator();

            // --- Основная область: делим на левую и правую части ---
            ImVec2 avail = ImGui::GetContentRegionAvail();
            float leftWidth = avail.x * 0.70f;
            float consoleHeight = 150.0f;  // фиксированная высота консоли
            float upperHeight = avail.y - consoleHeight;

            // Левая часть: дизассемблирование + регистры
            ImGui::BeginChild("MainLeftRight", ImVec2(0, upperHeight), false);

            // Левая панель: дизассемблирование
            ImGui::BeginChild("DisasmPanel", ImVec2(leftWidth, 0), true);
            renderDisassemblyArea();  // с вкладками
            ImGui::EndChild();

            ImGui::SameLine();

            // Правая панель: регистры
            ImGui::BeginChild("Registers", ImVec2(0, 0), true);
            renderRegisters();
            ImGui::EndChild();

            ImGui::EndChild(); // MainLeftRight

            // --- Консоль ---
            ImGui::BeginChild("Console", ImVec2(0, consoleHeight), true);
            renderConsole();
            ImGui::EndChild();

        }
        ImGui::End(); // "Debugger"

        if (!windowOpen)
            glfwSetWindowShouldClose(window, true);

        ImGui::Render();
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

}

GUI::~GUI() {
    if (succesInit)
    {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();

        glfwDestroyWindow(window);
        glfwTerminate();
    }
}


void GUI::setupDebuggerStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();

    // === Цвета ===
    style.Colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    style.Colors[ImGuiCol_PopupBg] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 1.00f);
    style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.16f, 0.16f, 1.00f);
    style.Colors[ImGuiCol_TitleBg] = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);

    // === Размеры ===
    style.WindowBorderSize = 1.5f;
    style.ChildBorderSize = 2.0f;
    style.FrameBorderSize = 1.0f;
    style.PopupBorderSize = 2.0f;

    // === Отступы ===
    style.WindowPadding = ImVec2(6, 6);
    style.FramePadding = ImVec2(5, 2);
}

bool GUI::openFilePicker()
{
    wchar_t filename[MAX_PATH] = { 0 };

    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;  
    ofn.lpstrFilter = L"Executable files\0*.exe;*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select program to debug";
    ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn))
    {

        int size = WideCharToMultiByte(CP_UTF8, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        std::string utf8Path(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, filename, -1, &utf8Path[0], size, nullptr, nullptr);

        if (!utf8Path.empty() && utf8Path.back() == '\0')
            utf8Path.pop_back();
        selectedProgram = utf8Path;

        if (onProgramSelected) 
            onProgramSelected(selectedProgram);  
        return true;
    }
    return false;
}

void GUI::renderToolbar()
{
    if (ImGui::Button("Open Program..."))
        openFilePicker();

    if (!selectedProgram.empty())
    {
        ImGui::SameLine();
        ImGui::Text("Selected: %s", selectedProgram.c_str());
        commandCallback(selectedProgram);
    }
    
    ImGui::Separator();
}

void GUI::pushEvent(const DebugEvent& event)
{
    std::lock_guard<std::mutex> lock(msgMutex);
    msgQueue.push(event);
}

void GUI::renderDisassemblyCode()
{
    const float lineHeight = 20.0f;

    if (updateIP)
    {
        int targetIndex = -1;
        for (int i = 0; i < static_cast<int>(disasCode.size()); ++i) {
            if (disasCode[i].address == currentIP) {
                targetIndex = i;
                break;
            }
        }

          // Средняя высота строки

        // === ШАГ 2: если нашли — принудительно установим скролл ДО клиппинга ===
        if (targetIndex != -1) {
            float targetPosY = targetIndex * lineHeight;
            float windowVisibleHeight = ImGui::GetContentRegionAvail().y;
            float scrollTarget = targetPosY - (windowVisibleHeight * 0.3f);  // чуть выше центра

            // Ограничиваем диапазон
            float maxScroll = max(0.0f, static_cast<float>(disasCode.size()) * lineHeight - windowVisibleHeight);
            scrollTarget = std::clamp(scrollTarget, 0.0f, maxScroll);

            ImGui::SetScrollY(scrollTarget);
        }

        updateIP = false;
    }
    // === ШАГ 3: рендерим как обычно ===
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(disasCode.size()), lineHeight);

    while (clipper.Step())
    {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            if (i >= disasCode.size()) continue;
            auto& line = disasCode[i];

            ImGui::PushID(i);

            ImVec2 cursorStart = ImGui::GetCursorScreenPos();

            // --- Кнопка точки останова ---
            if (ImGui::InvisibleButton("bp", ImVec2(20, lineHeight)))
                if (commandCallback)
                {
                    line.hasBreakpoint = !line.hasBreakpoint;
                    std::ostringstream oss;
                    oss << "bp 0x" << std::hex << line.address;
                    commandCallback(oss.str());
                }
            

            // Рисуем круг
            ImVec2 center = ImVec2(cursorStart.x + 10, cursorStart.y + lineHeight / 2);
            ImU32 color = IM_COL32(100, 100, 100, 100);
            if (line.hasBreakpoint) {
                color = IM_COL32(255, 0, 0, 200);
            }
            else if (line.address == currentIP) {
                color = IM_COL32(0, 255, 0, 200);
            }

            ImDrawList* drawList = ImGui::GetWindowDrawList();
            drawList->AddCircleFilled(center, 4.0f, color);

            ImGui::SameLine();

            // Подсветка EIP
            if (line.address == currentIP) {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 0, 255));
            }

            // Форматируем строку
            std::ostringstream oss;
            oss << std::hex << std::uppercase << std::setfill('0')
                << std::setw(8) << line.address
                << ": "
                << line.bytes
                << "  "
                << line.instruction;

            ImGui::TextUnformatted(oss.str().c_str());

            if (line.address == currentIP) {
                ImGui::PopStyleColor();
            }

            ImGui::PopID();
        }
    }
    clipper.End();
}



void GUI::renderDisassemblyArea()
{
    ImVec2 available = ImGui::GetContentRegionAvail();

    float tabBarHeight = 30.0f;


    ImGui::BeginChild("TabBarRegion", ImVec2(0, tabBarHeight), true);
    if (ImGui::BeginTabBar("DisasmTabs"))
    {
        if (ImGui::BeginTabItem("Code"))
        {
            currentTab = Tab::Code;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Data"))
        {
            currentTab = Tab::Data;
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Stack"))
        {
            currentTab = Tab::Stack;
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
    ImGui::EndChild();

    // Пространство под контент (с прокруткой)
    ImGui::BeginChild("TabContent", ImVec2(0, available.y - tabBarHeight), false);

    switch (currentTab) {
    case Tab::Code:
        renderDisassemblyCode();
        break;
    case Tab::Data:
        renderData();
        break;
    case Tab::Stack:
        renderStack();
        break;
    }

    ImGui::EndChild(); // TabContent
}


void GUI::renderDebugButtons()
{
    ImVec2 buttonSize(30, 30);

    ImU32 hoverColor = IM_COL32(100, 100, 100, 255);
    ImU32 activeColor = IM_COL32(150, 150, 150, 255);

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(60, 60, 60, 255));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hoverColor);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, activeColor);

    if (ImGui::Button("step_into", buttonSize))
        if (commandCallback) commandCallback("g");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Step Into (F7)");

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetItemRectMin();
    ImVec2 sz = ImGui::GetItemRectSize();

    float pad = 6.0f;
    draw->AddTriangleFilled(
        ImVec2(p.x + pad, p.y + pad),
        ImVec2(p.x + sz.x - pad, p.y + pad),
        ImVec2(p.x + sz.x / 2, p.y + sz.y - pad),
        ImGui::GetColorU32(ImGui::IsItemHovered() ? IM_COL32(0, 255, 0, 255) : IM_COL32(0, 200, 0, 255))
    );
    ImGui::SameLine();
    if (ImGui::Button("step_out", buttonSize))
        if (commandCallback) commandCallback("n");
    
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Step Out (F8)");

    ImVec2 p2 = ImGui::GetItemRectMin();
    ImVec2 sz2 = ImGui::GetItemRectSize();
    float pad2 = 6.0f;

    draw = ImGui::GetWindowDrawList();
    draw->AddQuadFilled(
        ImVec2(p2.x + pad2, p2.y + pad2),
        ImVec2(p2.x + sz2.x - pad2, p2.y + sz2.y / 2),
        ImVec2(p2.x + pad2, p2.y + sz2.y - pad2),
        ImVec2(p2.x + pad2, p2.y + sz2.y / 2),
        ImGui::GetColorU32(ImGui::IsItemHovered() ? IM_COL32(255, 255, 0, 255) : IM_COL32(200, 200, 0, 255))
    );
    ImGui::SameLine();
    // --- Step Over (F8) ---
    if (ImGui::Button("step_over", buttonSize))
        if (commandCallback) commandCallback("p");  // "p" = step over
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Step Over (F8)");

    p2 = ImGui::GetItemRectMin();
    sz2 = ImGui::GetItemRectSize();
    pad2 = 6.0f;

    // Квадрат с наклоном → стрелка вправо (шаг мимо)
    draw = ImGui::GetWindowDrawList();
    draw->AddQuadFilled(
        ImVec2(p2.x + pad2, p2.y + pad2),
        ImVec2(p2.x + sz2.x - pad2, p2.y + pad2 + 4),
        ImVec2(p2.x + sz2.x - pad2, p2.y + sz2.y - pad2 - 4),
        ImVec2(p2.x + pad2, p2.y + sz2.y - pad2),
        ImGui::GetColorU32(ImGui::IsItemHovered() ? IM_COL32(255, 255, 0, 255) : IM_COL32(200, 200, 0, 255))
    );
    ImGui::SameLine();
    if (ImGui::Button("run", buttonSize))
        if (commandCallback) commandCallback("run");
    
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Run (F9)");

    ImVec2 p3 = ImGui::GetItemRectMin();
    ImVec2 sz3 = ImGui::GetItemRectSize();
    float pad3 = 7.0f;

    draw = ImGui::GetWindowDrawList();
    draw->AddTriangleFilled(
        ImVec2(p3.x + pad3, p3.y + pad3),
        ImVec2(p3.x + pad3, p3.y + sz3.y - pad3),
        ImVec2(p3.x + sz3.x - pad3, p3.y + sz3.y / 2),
        ImGui::GetColorU32(ImGui::IsItemHovered() ? IM_COL32(0, 0, 255, 255) : IM_COL32(0, 0, 200, 255))
    );
    ImGui::SameLine();
    if (ImGui::Button("stop", buttonSize))
        if (commandCallback) commandCallback("stop");
    
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Stop");

    //ImVec2 p4 = ImGui::GetItemRectMin();
    //ImVec2 sz4 = ImGui::GetItemRectSize();
    //float pad4 = 8.0f;

    //draw = ImGui::GetWindowDrawList();
    //draw->AddRectFilled(
    //    ImVec2(p4.x + pad4, p4.y + pad4),
    //    ImVec2(p4.x + sz4.x - pad4, p4.y + sz4.y - pad4),
    //    ImGui::GetColorU32(ImGui::IsItemHovered() ? IM_COL32(255, 0, 0, 255) : IM_COL32(200, 0, 0, 255))
    //);
    ImGui::PopStyleColor();
    ImGui::PopStyleColor();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}

void GUI::renderRegisters() {


#ifdef _WIN64
    ImGui::Text("RAX: %016llX", context.Rax); ImGui::SameLine(300); ImGui::Text("RBX: %016llX", context.Rbx);
    ImGui::Text("RCX: %016llX", context.Rcx); ImGui::SameLine(300); ImGui::Text("RDX: %016llX", context.Rdx);
    ImGui::Text("RSI: %016llX", context.Rsi); ImGui::SameLine(300); ImGui::Text("RDI: %016llX", context.Rdi);
    ImGui::Text("RBP: %016llX", context.Rbp); ImGui::SameLine(300); ImGui::Text("RSP: %016llX", context.Rsp);
    ImGui::Text("RIP: %016llX", context.Rip);
#else
    ImGui::Text("EAX: %08X", context.Eax); ImGui::SameLine(200); ImGui::Text("EBX: %08X", context.Ebx);
    ImGui::Text("ECX: %08X", context.Ecx); ImGui::SameLine(200); ImGui::Text("EDX: %08X", context.Edx);
    ImGui::Text("ESI: %08X", context.Esi); ImGui::SameLine(200); ImGui::Text("EDI: %08X", context.Edi);
    ImGui::Text("EBP: %08X", context.Ebp); ImGui::SameLine(200); ImGui::Text("ESP: %08X", context.Esp);
    ImGui::Text("EIP: %08X", context.Eip);
#endif
    ImGui::Text("EFLAGS: %08X", context.EFlags);
}

void GUI::renderData()
{
    if (dataSections.empty()) {
        ImGui::Text("No data sections available.");
        return;
    }

    // Убедимся, что индекс валиден
    if (currentDataTabIndex < 0 || currentDataTabIndex >= static_cast<int>(dataSections.size())) {
        currentDataTabIndex = 0;
    }

    ImVec2 avail = ImGui::GetContentRegionAvail();
    const float tabBarHeight = 30.0f;

    // --- Tab Bar для секций ---
    ImGui::BeginChild("DataTabBar", ImVec2(0, tabBarHeight), true);
    if (ImGui::BeginTabBar("##DataSections", ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (int i = 0; i < static_cast<int>(dataSections.size()); ++i) {
            const char* name = dataSections[i].secName.c_str();
            // BeginTabItem возвращает true, если вкладка выбрана (и нужно отрендерить содержимое)
            if (ImGui::BeginTabItem(name)) {
                // Если мы здесь — пользователь переключился на эту вкладку
                if (currentDataTabIndex != i) {
                    currentDataTabIndex = i;
                    currentDataSection = dataSections[i];
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();

    // --- Содержимое текущей секции ---
    ImGui::BeginChild("DataContent", ImVec2(0, avail.y - tabBarHeight), false);

    const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(currentDataSection.data.size()), lineHeight);

    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            if (i >= static_cast<int>(currentDataSection.data.size())) continue;
            const auto& line = currentDataSection.data[i];

            std::ostringstream addrStream;
#ifdef _WIN64
            addrStream << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << line.address;
#else
            addrStream << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << line.address;
#endif

            std::string hexBytes = formatHex(line.bytes);
            std::string ascii = line.ascii.empty() ? formatAscii(line.bytes) : line.ascii;

            ImGui::Text("%s: %s", addrStream.str().c_str(), hexBytes.c_str());
            ImGui::SameLine();
            ImGui::Text("  ; %s", ascii.c_str());
        }
    }
    clipper.End();

    ImGui::EndChild();
}

void GUI::addToConsole(const std::string& line)
{
    consoleLines.push_back(line);
}

void GUI::addCmdToHistory(const std::string& cmd)
{
    if (!cmd.empty())
    {
        commandHistory.erase(
            std::remove(commandHistory.begin(), commandHistory.end(), cmd),
            commandHistory.end()
        );
        commandHistory.push_back(cmd);
    }
    historyPos = -1;
}

void GUI::renderConsole() {
    ImGui::BeginChild("ConsoleOutput", ImVec2(0, -40), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);

    // Вывод всех строк
    for (const auto& line : consoleLines) {
        ImGui::TextUnformatted(line.c_str());
    }

    // Авто-скролл вниз
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    // --- Поле ввода ---
    ImGui::PushItemWidth(-1);
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_EnterReturnsTrue |
        ImGuiInputTextFlags_CallbackHistory;

    bool reclaimFocus = false;

    if (ImGui::InputText("##console_input", inputBuf, IM_ARRAYSIZE(inputBuf), flags,
        [](ImGuiInputTextCallbackData* data) -> int {
            GUI* gui = (GUI*)data->UserData;
            return gui->textInputCallback(data);
        }, this))
    {
        if (strlen(inputBuf) > 0) {
            std::string cmd(inputBuf);

            // Добавляем в консоль
            addToConsole("> " + cmd);
            addCmdToHistory(cmd);

            // Отправляем отладчику
            if (commandCallback) {
                commandCallback(cmd);
            }

            // Очищаем поле
            inputBuf[0] = '\0';
            reclaimFocus = true;
        }
    }

    ImGui::PopItemWidth();

    // Фокус после отправки
    if (reclaimFocus) {
        ImGui::SetKeyboardFocusHere(-1);
    }
}

int GUI::textInputCallback(ImGuiInputTextCallbackData* data)
{
    switch (data->EventFlag) {
    case ImGuiInputTextFlags_CallbackHistory:
        if (commandHistory.empty()) return 0;

        // Стрелка вверх
        if (data->EventKey == ImGuiKey_UpArrow) {
            if (historyPos == -1)
                historyPos = (int)commandHistory.size() - 1;
            else if (historyPos > 0)
                historyPos--;

            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, commandHistory[historyPos].c_str());
        }

        // Стрелка вниз
        else if (data->EventKey == ImGuiKey_DownArrow) {
            if (historyPos != -1) {
                historyPos++;
                if (historyPos >= (int)commandHistory.size()) {
                    historyPos = -1;
                    data->DeleteChars(0, data->BufTextLen);
                }
                else {
                    data->DeleteChars(0, data->BufTextLen);
                    data->InsertChars(0, commandHistory[historyPos].c_str());
                }
            }
        }
        break;
    }
    return 0;
}

void GUI::update(const DebugEvent& de) 
{
    std::lock_guard<std::mutex> lock(msgMutex);
    msgQueue.push(de);
}


void GUI::renderStack() {
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(stack.size()));

    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            if (i >= stack.size()) continue;
            const auto& line = stack[i];

            ImGui::PushID(i);

            // Форматируем адрес и значение с использованием C++ потоков
            std::ostringstream addrStream;
            std::ostringstream valueStream;

            // Настройка потоков
            addrStream << std::hex << std::uppercase << std::setfill('0');
            valueStream << std::hex << std::uppercase << std::setfill('0');

            // Установка ширины в зависимости от разрядности
#ifdef _WIN64
            addrStream << std::setw(16) << line.address;
            valueStream << std::setw(16) << line.value;
#else
            addrStream << std::setw(8) << line.address;
            valueStream << std::setw(8) << line.value;
#endif

            // Выделяем текущий ESP/RSP
            bool isCurrent = (line.address ==
#ifdef _WIN64
                context.Rsp
#else
                context.Esp
#endif
                );

            if (isCurrent) {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 0, 255));
                ImGui::Text("> %s: %s", addrStream.str().c_str(), valueStream.str().c_str());
                ImGui::PopStyleColor();
            }
            else {
                ImGui::Text("%s: %s", addrStream.str().c_str(), valueStream.str().c_str());
            }

            if (!line.label.empty()) {
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(100, 200, 100, 255));
                ImGui::Text("  ; %s", line.label.c_str());
                ImGui::PopStyleColor();
            }

            ImGui::PopID();
        }
    }
    clipper.End();
}