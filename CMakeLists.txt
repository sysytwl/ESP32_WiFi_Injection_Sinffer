if(DEFINED ENV{IDF_PATH})
    file(GLOB srcs
        "src/*.c"
        "src/*.cpp"
    )

    idf_component_register(
        SRCS ${srcs}
        INCLUDE_DIRS "include" 
        PRIV_REQUIRES esp_wifi nvs_flash esp_timer
    )
else()
    # 设置C标准
    set(CMAKE_C_STANDARD 99)
    set(CMAKE_C_STANDARD_REQUIRED ON)

    # 源文件
    set(SRC_FILES
        "src/empty.cpp"
    )

    # 头文件目录
    include_directories( ./include)

    # 生成静态库
    add_library(ESP32_WiFi_Injection_Sinffer STATIC ${SRC_FILES})
endif()