set(files "${CMAKE_CURRENT_LIST_DIR}/CanPacket.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CreateMove.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/DispatchUserMessage.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/EmitSound.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/FireGameEvent.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/GetFriendPersonaName.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/GetUserCmd.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/LevelInit.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/LevelShutdown.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/nographics.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/others.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/Paint.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/PlayerAnimFix.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/RandomInt.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/RunCommand.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SendNetMsg.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/Shutdown.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/Think.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/FireEvent.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/FireEventClientSide.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IsPlayingTimeDemo.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/HookTools.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SendDatagram.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/ClassIdTranslator.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/ClassInfoEndClasses.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/ParsePacketEntities.cpp")

# Generate EmbeddedClassInfo.cpp from txt dumps so the lists are compiled in
set(_txt_dir "${CMAKE_CURRENT_LIST_DIR}/txt")
set(_x32_txt "${_txt_dir}/x32parseclassinfo")
set(_x64_txt "${_txt_dir}/x64parseclassinfo")
set(_tpl     "${CMAKE_CURRENT_LIST_DIR}/EmbeddedClassInfo.tpl.cpp")
set(_gen     "${CMAKE_CURRENT_BINARY_DIR}/EmbeddedClassInfo.cpp")

if(EXISTS "${_x32_txt}" AND EXISTS "${_x64_txt}" AND EXISTS "${_tpl}")
    file(READ "${_x32_txt}" X32_CONTENT)
    file(READ "${_x64_txt}" X64_CONTENT)
    # Configure the template with raw string literals
    configure_file("${_tpl}" "${_gen}" @ONLY)
    list(APPEND files "${_gen}")
    message(STATUS "EmbeddedClassInfo.cpp generated from txt dumps")
else()
    message(WARNING "Embedded class info not generated: missing txt or template. Runtime file loading will be used.")
endif()
target_sources(cathook PRIVATE ${files})

if(EnableVisuals)
    add_subdirectory(visual)
endif()
if(Textmode)
    add_subdirectory(textmode)
endif()
