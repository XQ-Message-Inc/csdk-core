add_subdirectory( quantum )
add_subdirectory( sub )
add_subdirectory( val )
add_subdirectory( dashboard )

target_sources(xqc PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/crypto.c
	${CMAKE_CURRENT_LIST_DIR}/decrypt.c
	${CMAKE_CURRENT_LIST_DIR}/encrypt.c
	${CMAKE_CURRENT_LIST_DIR}/decrypt_file.c
	${CMAKE_CURRENT_LIST_DIR}/encrypt_file.c
)