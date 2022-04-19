#include "Util.h"

#include "pin.H"


std::string util::FileBasename(const std::string &str)
{
	std::size_t found = str.find_last_of("/\\");
	std::string name = str.substr(found + 1);
	std::transform(name.begin(), name.end(), name.begin(), std::tolower);
	return name;
}

std::string util::WcharToString(wchar_t* src) {
	std::wstringstream wss;
	wss << "L\"" << src << "\"";
	std::wstring ws = wss.str();
	return std::string(ws.begin(), ws.end());
}
