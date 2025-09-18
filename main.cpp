#include "debugger.hpp"
//#define STB_IMAGE_IMPLEMENTATION
//#include <glad/glad.h>
//#include <GLFW/glfw3.h>
//
//#define IMGUI_DISABLE_STB_TEXTEDIT
//#include <imgui.h>
//#include <imgui_impl_glfw.h>
//#include <imgui_impl_opengl3.h>

int main(size_t argc, char** argv, char** envp)
{
	Debugger debug = Debugger();
	debug.run(argv[1]);
	return 0;
//    if (!glfwInit()) return -1;
//
//    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
//    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
//    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
//
//#ifdef __APPLE__
//    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
//#endif
//
//    GLFWwindow* window = glfwCreateWindow(1280, 720, "Debugger", nullptr, nullptr);
//    if (!window) return -1;
//
//    glfwMakeContextCurrent(window);
//    glfwSwapInterval(1);
//
//    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) return -1;
//
//    IMGUI_CHECKVERSION();
//    ImGui::CreateContext();
//    ImGuiIO& io = ImGui::GetIO();
//    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
//    ImGui::StyleColorsDark();
//
//    ImGui_ImplGlfw_InitForOpenGL(window, true);
//    ImGui_ImplOpenGL3_Init("#version 330");
//
//    while (!glfwWindowShouldClose(window)) {
//        glfwPollEvents();
//
//        ImGui_ImplOpenGL3_NewFrame();
//        ImGui_ImplGlfw_NewFrame();
//        ImGui::NewFrame();
//
//        ImGui::Begin("Debugger");
//        ImGui::Button("Step Into");
//        static int counter = 0;
//        if (ImGui::Button("+")) counter++;
//        ImGui::Text("Counter: %d", counter);
//        ImGui::End();
//
//        ImGui::Render();
//        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
//        glClear(GL_COLOR_BUFFER_BIT);
//        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
//
//        glfwSwapBuffers(window);
//    }
//
//    ImGui_ImplOpenGL3_Shutdown();
//    ImGui_ImplGlfw_Shutdown();
//    ImGui::DestroyContext();
//
//    glfwDestroyWindow(window);
//    glfwTerminate();
//    return 0;
}