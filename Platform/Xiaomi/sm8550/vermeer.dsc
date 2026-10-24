## @file
#
#  Redmi K70 (vermeer) — SM8550 platform
#  以 Xiaomi 13 (fuxi) 的配置为模板移植，平台层完全复用 Platform/Qualcomm/sm8550。
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  VENDOR_NAME                    = Xiaomi
  PLATFORM_NAME                  = vermeer
  PLATFORM_GUID                  = 130a0e0e-f784-496c-8006-37f3cc6e90a8
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010019
  OUTPUT_DIRECTORY               = Build/$(PLATFORM_NAME)
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = Platform/Qualcomm/sm8550/sm8550.fdf
  DEVICE_DXE_FV_COMPONENTS       = Platform/Xiaomi/sm8550/vermeer.fdf.inc

!include Platform/Qualcomm/sm8550/sm8550.dsc

[BuildOptions.common]
  GCC:*_*_AARCH64_CC_FLAGS = -DENABLE_SIMPLE_INIT

[PcdsFixedAtBuild.common]
  # 红米 K70 面板：1440 x 3200，6.67 英寸，PPI ≈ 526
  # 原厂 dmesg 实测 panel 为 qcom,mdss_dsi_n11_42_02_0a_dsc_cmd
  gQcomTokenSpaceGuid.PcdMipiFrameBufferWidth|1440
  gQcomTokenSpaceGuid.PcdMipiFrameBufferHeight|3200

  # Simple Init
  gSimpleInitTokenSpaceGuid.PcdGuiDefaultDPI|526

  gRenegadePkgTokenSpaceGuid.PcdDeviceVendor|"Xiaomi"
  gRenegadePkgTokenSpaceGuid.PcdDeviceProduct|"Redmi K70"
  gRenegadePkgTokenSpaceGuid.PcdDeviceCodeName|"vermeer"
