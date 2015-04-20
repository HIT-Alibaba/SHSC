add_executable(share_atomic_test share_atomic_test.cc)
target_link_libraries(share_atomic_test shsc)

add_executable(share_queue_test share_queue_test.cc)
target_link_libraries(share_queue_test shsc)

add_executable(share_threadpool_test share_threadpool_test.cc)
target_link_libraries(share_threadpool_test shsc)

add_executable(net_buffer_test net_buffer_test.cc)
target_link_libraries(net_buffer_test shsc)

add_executable(net_inet_address_test net_inet_address_test.cc)
target_link_libraries(net_inet_address_test shsc)

add_executable(ssl_test test_ssl.cc)
target_link_libraries(ssl_test shsc)

add_executable(imageserver_test test_imageserver.cc)
target_link_libraries(imageserver_test shsc)


