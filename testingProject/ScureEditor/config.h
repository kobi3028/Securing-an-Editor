#include "stdafx.h"

class config
{
public:
	std::string PrivateKeyLocation;
	size_t RefersToThePublicKeyNumber;
	size_t NumberOfPublicKey;
	std::vector<std::string> PublicKeyList;
	config()
	{
		using namespace rapidjson;
		FILE* fp = fopen("config.xml", "rb"); // non-Windows use "r"
		int result = 0;
		//check file size
		struct stat stat_buf;
		int rc = stat("config.xml", &stat_buf);
		rc == 0 ? result = stat_buf.st_size : result = -1;
		//
		if (result > 4095)
		{
			MessageBox(NULL, L"Big Config File", NULL, 1);
			exit(3);
		}
		char readBuffer[4096];
		FileReadStream bis(fp, readBuffer, sizeof(readBuffer));
		fclose(fp);
		EncodedInputStream<UTF16LE<>, FileReadStream> eis(bis);  // wraps bis into eis
		Document d; // Document is GenericDocument<UTF8<> > 
		bool res = d.Parse(readBuffer).HasParseError();  // Parses UTF-16LE file into UTF-8 in memory
		if (res)
		{
			MessageBox(NULL, L"Unvalid Config File", NULL, 1);
			exit(3);
		}
		PrivateKeyLocation = d["configuration"]["PrivateKey"]["PrivateKeyLocation"].GetString();
		int temp = d["configuration"]["PrivateKey"]["RefersToThePublicKeyNumber"].GetInt();
		if (temp > 0)
			RefersToThePublicKeyNumber = temp;
		temp = 0;
		temp = d["configuration"]["PublicKey"]["NumberOfPublicKey"].GetInt();
		if (temp > 0)
			NumberOfPublicKey = temp;
		const Value& itr = d["configuration"]["PublicKey"]["PublicKeyList"];
		assert(itr.IsArray());
		for (SizeType i = 0; i < itr.Size(); i++) // Uses SizeType instead of size_t
		{
			std::string insert(itr[i]["PublicKeyLocation"].GetString());
			PublicKeyList.push_back(insert);
		}
		fclose(fp);
	}
	~config()
	{
		PrivateKeyLocation.clear();
		PublicKeyList.clear();
	}
};