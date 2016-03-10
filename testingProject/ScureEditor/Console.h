#pragma once
#include <stdio.h>

class CConsole {
	FILE m_OldStdin, m_OldStdout;
	bool m_OwnConsole;
public:
	CConsole();
	~CConsole();
};