#include <jni.h>
#include <string>
#include <stdlib.h>
#include <thread>

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doUseAfterFree(
        JNIEnv *env,
        jobject /* this */) {
    char * volatile p = new char[10];
    delete[] p;
    p[5] = 42;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doHeapBufferOverflow(
        JNIEnv *env,
        jobject /* this */) {
    char * volatile p = new char[16];
    p[16] = 42;
    delete[] p;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doHeapBufferOverflowReadLoop(
        JNIEnv *env,
        jobject /* this */) {
    for (int i = 0; i < 0x10000; ++i) {
        char * volatile p = new char[16];
        volatile char x = p[32];
        x++;
        delete[] p;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doDoubleFree(
        JNIEnv *env,
        jobject /* this */) {
    char * volatile p = new char[16];
    delete[] p;
    delete[] p;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doNullDeref(
        JNIEnv *env,
        jobject /* this */) {
    char * volatile p = (char *)nullptr;
    p[42] = 1;
}


static void RunUAFLoop() {
    constexpr int kLoopCount = 100;
    constexpr int kAllocCount = 1000;
    volatile char sink;
    char **p = new char*[kAllocCount];
    for (int j = 0; j < kLoopCount; ++j) {
        for (int i = 0; i < kAllocCount; ++i)
            p[i] = new char[128];
        for (int i = 0; i < kAllocCount; ++i)
            delete[] p[i];
        for (int i = 0; i < kAllocCount; ++i)
            sink = p[i][42];
    }
    delete[] p;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_sanitizertest_MainActivity_doUseAfterFreeLoop(
        JNIEnv *env,
        jobject /* this */) {
    std::thread t(RunUAFLoop);
    t.detach();
}
