# Securing-an-Editor

-------------------------
Introduction
-------------------------
The aim of the project is to adding security capabilities to an existing program that allows keeping the simplicity of using that program and in addition encrypt all documents generated by it.
Secure an Editor
The project aims to produce an extension to an existing product without changing the PE file, the product will be transparent to the user but will add option of encrypt files (possibly even without the user's knowledge), In order to achieve the goal the project will produce a DLL, then using techniques of DLL INJECTION to inject the DLL into a running process and API HOOKING for the purpose of monitoring system functions such as writing, reading and opening a file and then calling functions from the DLL for encrypt or decrypt the file before reading or writing it.
In order to allow the reading of the document by a third party (could be sending a document to another user, a demand of IT staff in the company or even as a backup), The program will support in hierarchy of keys to allow more than one entity to decrypt the file.
All work on the project was on notepad ++ text editor 64 bit edition, this is a very common open source text editor, used by end users of all kinds.
Most thought in the project was a practical product to require as little user intervention to “Keep it simple” without the requirement of multiple passwords and so on.

