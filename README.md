# VMWare VGPU Direct 3D 10 Shader PoCs

This repository contains PoCs for VMWare VGPU Direct 3D 10 shader translation vulnerabilities discovered by Comsecuris and described in our [blog post](https://comsecuris.com/blog/posts/vmware_vgpu_shader_vulnerabilities/).
Each directory contains one or more (two in the case of customdata) examples of triggering the issue from a Windows 10 guest (KB4013429).

* dcl_immediateconstantbuffer/ Heap overflow when translating dcl_immediateConstantBuffer opcodes
  * fixed in VMWare Workstation 12.5.5
* dcl_indexabletemp/ Out-of-bounds heap write when translating dcl_indexableTemp opcodes
  * fixed in VMWare Workstation 12.5.5
* dcl_resource/ Out-of-bounds stack buffer write when translating dcl_resource opcodes
  * fixed in VMWare Workstation 12.5.7

As we did not utilize fuzzing to identify these issues, but manually found these during reverse engineering, we needed a flexible tool in order
to craft test cases in user-space while not having to worry too much about the Windows Direct 3D api itself.
As a result, we have used [frida](http://frida.re) to inject our payload into memory at the desired code locations.
All of this can be done in user-space from an unprivileged guest user.

Preparation/Installation
========================
In order to use the PoCs, python and frida need to be installed.

* 1.) Download and install https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi
* 2.) Use pip.exe from the python installations script directory to install frida with pip.exe install frida

PoC Files
=========
Each directory contains a python script that is used as the main launcher to execute the poc. It calls poc.exe, which is a shader test program.
poc.exe in turn uses poc.fx, which is an HLSL shader file as a dummy for compilation and deploying shaders.
Once the shader is compiled and has passed all D3D MS APIs, we overwrite the compiled shader code with our payload using Frida.
The Frida part resides in the python script. Execution takes a few seconds (due to a few sleep statements) to make sure hooking works reliable.
