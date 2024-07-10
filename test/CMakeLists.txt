cmake_minimum_required (VERSION 2.8...3.10)

project(${lib_name}_test)

set(proto_test_main plugin_test_main)
set(PROTO_TEST_RUN_DIR ${CMAKE_INSTALL_PREFIX}/sapp)

add_library(${lib_name}_test_plug SHARED ${lib_name}_test_plug.cpp)
target_link_libraries(${lib_name}_test_plug MESA_prof_load cjson)
set_target_properties(${lib_name}_test_plug  PROPERTIES PREFIX "")

add_test(NAME COPY_QUIC_SO COMMAND sh -c "mkdir -p ${PROTO_TEST_RUN_DIR}/stellar_plugin/${lib_name} && cp ${CMAKE_BINARY_DIR}/src/${lib_name}.so ${PROTO_TEST_RUN_DIR}/stellar_plugin/${lib_name}/${lib_name}.so")
add_test(NAME COPY_TEST_SO COMMAND sh -c "mkdir -p ${PROTO_TEST_RUN_DIR}/stellar_plugin/${lib_name} && cp ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}_test_plug.so ${PROTO_TEST_RUN_DIR}/stellar_plugin/${lib_name}/${lib_name}_test_plug.so")
add_test(NAME COPY_TEST_SPEC COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/quic.inf ${PROTO_TEST_RUN_DIR}/stellar_plugin/spec.toml")
add_test(NAME COPY_PLUGIN_TEST_MAIN COMMAND sh -c "rpm -ql sapp | grep plugin_test_main | xargs -i cp -f {} ${PROTO_TEST_RUN_DIR}/")
add_test(NAME COPY_MAIN_CFG COMMAND sh -c "mkdir -p ${PROTO_TEST_RUN_DIR}/conf/quic_decoder && cp ${CMAKE_SOURCE_DIR}/bin/main.conf  ${PROTO_TEST_RUN_DIR}/conf/quic_decoder/")
add_test(NAME COPY_QUIC_CFG COMMAND sh -c "mkdir -p ${PROTO_TEST_RUN_DIR}/conf/quic_decoder && cp ${CMAKE_SOURCE_DIR}/bin/quic.conf  ${PROTO_TEST_RUN_DIR}/conf/quic_decoder/")
add_test(NAME UPDATE_SAPP_LOG_LEVEL COMMAND bash -c "sed -i 's/sapp_log.fatal/sapp_log.info/' ${PROTO_TEST_RUN_DIR}/etc/sapp_log.conf")

set_tests_properties(COPY_QUIC_SO COPY_TEST_SO COPY_TEST_SPEC COPY_PLUGIN_TEST_MAIN COPY_MAIN_CFG COPY_QUIC_CFG  UPDATE_SAPP_LOG_LEVEL
                    PROPERTIES FIXTURES_SETUP TestFixture)

add_test(NAME IQUIC_29_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/iquic/29/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/iquic/29/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_23_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/23/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/23/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_25_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/25/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/25/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_33_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/33/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/33/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_34_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/34/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/34/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_35_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/35/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/35/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_37_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/37/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/37/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_39_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/39/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/39/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_41_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/41/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/41/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_43_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/43/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/43/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_44_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/44/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/44/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_46_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/46/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/46/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME GQUIC_50_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/50/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gquic/50/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME MVFST_01_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/mvfst/01/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/mvfst/01/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME MVFST_02_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/mvfst/02/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/mvfst/02/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME TQUIC_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/tquic/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/tquic/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME IQUIC_PORT_8443_TEST COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/port-8443/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/port-8443/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_RFC9000 COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_RFC9000_FRAGMENT COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-fragment/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-fragment/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_RFC9000_SPECIAL COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-special/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-special/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_AIRPORT COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/airport/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/airport -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_SPECIAL COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/special/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/special/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME QUIC_RFC9000_CHLO_FRAGMENT COMMAND ./${proto_test_main} ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-chlo-fragment/quic_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/rfc9000-chlo-fragment/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})

set_tests_properties(IQUIC_29_TEST
  GQUIC_23_TEST
  GQUIC_25_TEST
  GQUIC_33_TEST
  GQUIC_34_TEST
  GQUIC_35_TEST
  GQUIC_37_TEST
  GQUIC_39_TEST
  GQUIC_41_TEST
  GQUIC_43_TEST
  GQUIC_44_TEST
  GQUIC_46_TEST
  GQUIC_50_TEST
  MVFST_01_TEST
  MVFST_01_TEST
  MVFST_02_TEST
  TQUIC_TEST
  IQUIC_PORT_8443_TEST
  QUIC_RFC9000
  QUIC_RFC9000_FRAGMENT
  QUIC_RFC9000_SPECIAL
  QUIC_AIRPORT
  QUIC_SPECIAL
  QUIC_RFC9000_CHLO_FRAGMENT
  PROPERTIES FIXTURES_REQUIRED TestFixture)
  