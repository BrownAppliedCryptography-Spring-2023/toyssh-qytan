cmake_minimum_required(VERSION 3.10)

# project details
project(ToySSH VERSION 1.0)
set(CLIENT_EXEC_NAME toy_ssh)
set(SERVER_EXEC_NAME toy_sshd)
set(LIBRARY_NAME toy_ssh_lib)
set(LIBRARY_NAME_CRYPTO tinyssh)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
include(Cryptopp)

# set(SOURCES_CRYPTO
#   libtinyssh/src/blocking.c
#   libtinyssh/src/buf.c
#   libtinyssh/src/byte.c
#   libtinyssh/src/channel.c
#   libtinyssh/src/channel_drop.c
#   libtinyssh/src/channel_fork.c
#   libtinyssh/src/channel_forkpty.c
#   libtinyssh/src/channel_subsystem.c
#   libtinyssh/src/coe.c
#   libtinyssh/src/connectioninfo.c
#   libtinyssh/src/die.c
#   libtinyssh/src/dropuidgid.c
#   libtinyssh/src/e.c
#   libtinyssh/src/env.c
#   libtinyssh/src/getln.c
#   libtinyssh/src/global.c
#   libtinyssh/src/iptostr.c
#   libtinyssh/src/load.c
#   libtinyssh/src/log.c
#   libtinyssh/src/loginshell.c
#   libtinyssh/src/logsys.c
#   libtinyssh/src/main_tinysshd.c
#   libtinyssh/src/main_tinysshd_makekey.c
#   libtinyssh/src/main_tinysshd_printkey.c
#   libtinyssh/src/newenv.c
#   libtinyssh/src/numtostr.c
#   libtinyssh/src/open.c
#   libtinyssh/src/packet.c
#   libtinyssh/src/packet_auth.c
#   libtinyssh/src/packet_channel_open.c
#   libtinyssh/src/packet_channel_recv.c
#   libtinyssh/src/packet_channel_request.c
#   libtinyssh/src/packet_channel_send.c
#   libtinyssh/src/packet_get.c
#   libtinyssh/src/packet_hello.c
#   libtinyssh/src/packet_kex.c
#   libtinyssh/src/packet_kexdh.c
#   libtinyssh/src/packet_put.c
#   libtinyssh/src/packet_recv.c
#   libtinyssh/src/packet_send.c
#   libtinyssh/src/packet_unimplemented.c
#   libtinyssh/src/packetparser.c
#   libtinyssh/src/porttostr.c
#   libtinyssh/src/randommod.c
#   libtinyssh/src/readall.c
#   libtinyssh/src/savesync.c
#   libtinyssh/src/ssh.c
#   libtinyssh/src/sshcrypto.c
#   libtinyssh/src/sshcrypto_cipher.c
#   libtinyssh/src/sshcrypto_cipher_aesctr.c
#   libtinyssh/src/sshcrypto_cipher_aesctr256.c
#   libtinyssh/src/sshcrypto_cipher_chachapoly.c
#   libtinyssh/src/sshcrypto_kex.c
#   libtinyssh/src/sshcrypto_kex_curve25519.c
#   libtinyssh/src/sshcrypto_kex_nistp256.c
#   libtinyssh/src/sshcrypto_key.c
#   libtinyssh/src/sshcrypto_key_ed25519.c
#   libtinyssh/src/sshcrypto_key_nistp256ecdsa.c
#   libtinyssh/src/str.c
#   libtinyssh/src/stringparser.c
#   libtinyssh/src/subprocess_auth.c
#   libtinyssh/src/subprocess_sign.c
#   libtinyssh/src/tinysshd-makekey.c
#   libtinyssh/src/tinysshd-printkey.c
#   libtinyssh/src/tinysshd.c
#   libtinyssh/src/trymlock.c
#   libtinyssh/src/writeall.c)
# add_library(${LIBRARY_NAME_CRYPTO} ${SOURCES_CRYPTO})
# target_include_directories(${LIBRARY_NAME_CRYPTO} PUBLIC ${PROJECT_SOURCE_DIR}/libtinyssh/include)
# target_link_libraries(${LIBRARY_NAME_CRYPTO} PUBLIC ${PROJECT_SOURCE_DIR}/libtinyssh/lib/libtinynacl.a)

set(SOURCES
  src/pkg/ssh_client.cxx
  src/drivers/network_driver.cxx
  src/drivers/crypto_driver.cxx
  src/util/messages.cxx
  src/util/logger.cxx
  src/util/util.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME} PRIVATE cryptopp)
target_link_libraries(${LIBRARY_NAME} PRIVATE cryptopp-shared)
# target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_CRYPTO})

add_executable(${CLIENT_EXEC_NAME} src/cmd/client.cxx)
target_link_libraries(${CLIENT_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME}
      PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS YES
)

