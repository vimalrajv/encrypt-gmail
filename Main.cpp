#include "Main.h"

void Main::getMessageIds(boost::property_tree::ptree const& pt, std::vector<std::string>& messageIds)
{
	
	if (DEBUG)
		std::cout << "Main::getMessageIds " << std::endl;
	using boost::property_tree::ptree;
	ptree::const_iterator end = pt.end();
	for (ptree::const_iterator it = pt.begin(); it != end; ++it) {
		if ( it->first.compare("id") == 0 )
		{
			//std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			messageIds.push_back(it->second.get_value<std::string>());
		}
		getMessageIds(it->second, messageIds);
	}
}


void Main::getNameValueData(boost::property_tree::ptree const& pt, std::vector<std::string>& name, std::vector<std::string>& value, std::vector<std::string>& data )
{
	using boost::property_tree::ptree;
	ptree::const_iterator end = pt.end();
	for (ptree::const_iterator it = pt.begin(); it != end; ++it) {
		//std::cout << it->first << ": " << it->second.get_value<std::string>() << std::endl;
		if ( it->first.compare("name") == 0 )
		{
			//std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			name.push_back(it->second.get_value<std::string>() );
		}
		if ( it->first.compare("value") == 0 )
		{
			//std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			value.push_back(it->second.get_value<std::string>() );
		}
		if ( it->first.compare("data") == 0 )
		{
			//std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			data.push_back(it->second.get_value<std::string>() );
		}

		getNameValueData(it->second, name, value, data);
	}
}

std::string Main::AESEncryptData(std::string& plainText)
{
	//Key and IV setup
	//AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
	//bit). This key is secretly exchanged between two parties before communication   
	//begins. DEFAULT_KEYLENGTH= 16 bytes
	if (DEBUG)
		std::cout << "Main::Encrypting data with AES... " << std::endl;

	byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
	memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
	memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

	std::string ciphertext;

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
	stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1 );
	stfEncryptor.MessageEnd();

	//std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;

	std::string encrypted;
	CryptoPP::StringSource ss( ciphertext, true,  new CryptoPP::HexEncoder( new CryptoPP::StringSink( encrypted ) ) ); // StringSource
	//std::cout << "cipher text: " << encrypted << std::endl;

	return encrypted;

}

void Main::prepareRawJson(std::vector<std::string>& name, std::vector<std::string>& value, std::vector<std::string>& data, std::string& rawJson )
{
	if (DEBUG)
		std::cout << "Main::prepareRawJson: Creating Json " << std::endl;
	// From
	// To
	// Subject
	// Date
	// Message-ID 
	// Data
	int pos;

	pos = std::find(name.begin(), name.end(), "from" ) - name.begin();
	rawJson += "From: " ;
	rawJson += value[pos];
	rawJson += "\n"; 

	pos = std::find(name.begin(), name.end(), "to" ) - name.begin();
	rawJson += "To: " ;
	rawJson += value[pos]; 
	rawJson += "\n"; 

	pos = std::find(name.begin(), name.end(), "subject" ) - name.begin();
	rawJson += "Subject: " ;
	rawJson += value[pos]; 
	rawJson += "\n"; 

	pos = std::find(name.begin(), name.end(), "date" ) - name.begin();
	rawJson += "Date: " ;
	rawJson += value[pos]; 
	rawJson += "\n"; 

	if ( std::find(name.begin(), name.end(), "Message-ID") != name.end() )
	{ 
		pos = std::find(name.begin(), name.end(), "Message-ID" ) - name.begin();
		rawJson += "Message-ID: " ;
		rawJson += value[pos]; 
		rawJson += "\n";
	}
	else if ( std::find(name.begin(), name.end(), "Message-Id") != name.end() )
	{
		pos = std::find(name.begin(), name.end(), "Message-Id" ) - name.begin();
		rawJson += "Message-Id: " ;
		rawJson += value[pos]; 
		rawJson += "\n";
	}
	else {
		rawJson += "Message-Id: " ;
		rawJson += "RandomMessageId";
		rawJson += "\n";
	}

	//std::cout << "rawJson " << rawJson << std::endl;

	if (DEBUG)
		std::cout << "Main::prepareRawJson: decoding Json " << std::endl;


	for ( int i = 0; i < data.size(); i++ )
	{
		// RFC 2822
		replace(data[i].begin(), data[i].end(), '-', '+');
		replace(data[i].begin(), data[i].end(), '_', '/');

		std::string decoded;
		CryptoPP::StringSource ss(data[i], true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

		if (DEBUG)
			std::cout << "Main::prepareRawJson: AES Encrypting data " << std::endl;

		//std::cout << "Encrypted data " << AESEncryptData(data[i]) << std::endl;

		rawJson += AESEncryptData(decoded);
		rawJson += "\n";

	} 

	//std::cout << rawJson << std::endl; 

}

void Main::getMessageIdsFromJson(boost::property_tree::ptree const& pt, std::vector<std::string>& messageIds)
{
	if (DEBUG )
		std::cout << "Main::getMessageIdsFromJson " << std::endl;
	using boost::property_tree::ptree;
	ptree::const_iterator end = pt.end();
	for (ptree::const_iterator it = pt.begin(); it != end; ++it) {
		//std::cout << it->first << ": " << it->second.get_value<std::string>() << std::endl;
		if ( it->first.compare("id") == 0 )
		{
			if (DEBUG )
				std::cout << "Main::getMessageIdsFromJson " << it->first << " : " << it->second.get_value<std::string> () << std::endl;	
			messageIds.push_back(it->second.get_value<std::string>());
		}
		getMessageIdsFromJson(it->second, messageIds);
	}
}

void Main::getMessageIdsInRange(std::string& userId, std::string& dateRange, std::string& accessToken, std::vector<std::string>& messageIds)
{
	if (DEBUG )
		std::cout << "Main::getMessageIdsInRange " << std::endl;
	std::string getURL;
	getURL += "https://www.googleapis.com/gmail/v1/users/";
	getURL += userId;
	getURL += "/messages?q=";
	getURL += dateRange;
	getURL += "&access_token=";
	getURL += accessToken;

	if (DEBUG )
		std::cout << "Main::getMessageIdsInRange: getURL " << getURL <<  std::endl;

	RestClient::Response r = RestClient::get(getURL);
	std::stringstream buffer(r.body);

	// TODO
	// Capture the r.body status and check if authorization is successful!
	// std::cout << r.body << std::endl;

	boost::property_tree::ptree pt;
	boost::property_tree::read_json(buffer, pt);

	getMessageIdsFromJson(pt,messageIds);	

}

std::string Main::urlencode(const std::string &s)
{
	//RFC 3986 section 2.3 Unreserved Characters (January 2005)
	const std::string unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

	std::string escaped="";
	for(size_t i=0; i<s.length(); i++)
	{
		if (unreserved.find_first_of(s[i]) != std::string::npos)
		{
			escaped.push_back(s[i]);
		}
		else
		{
			escaped.append("%");
			char buf[3];
			sprintf(buf, "%.2X", s[i]);
			escaped.append(buf);
		}
	}
	return escaped;
}

void Main::getMessageJson(boost::property_tree::ptree& pt, std::string& userId, std::string& messageId, std::string& accessToken)
{
	if (DEBUG)
		std::cout << "Main::getMessageJson " << std::endl;
	std::string getURL;
	getURL += "https://www.googleapis.com/gmail/v1/users/" ;
	getURL += userId;
	getURL += "/messages/" ;
	getURL += messageId;
	getURL += "?access_token=";
	getURL += accessToken;

	if (DEBUG )
		std::cout << "Main::getMessageJson: getURL " << getURL << std::endl;

	RestClient::Response r = RestClient::get(getURL);
	std::stringstream buffer(r.body);
	//std::cout << r.body << std::endl;
	boost::property_tree::read_json(buffer, pt);
}

void Main::insertMessage(std::string& userId, std::string& base64Message, std::string& accessToken)
{

	if (DEBUG )
		std::cout << "Main::insertMessage " << std::endl;
	using boost::property_tree::ptree;

	std::string label = "INBOX";

	ptree pt;
	ptree lab;
	ptree labV;
	//labV.push_back(std::make_pair("",label));
	labV.put("",label);
	lab.push_back(std::make_pair("",labV));

	pt.put("raw", base64Message);
	pt.add_child("labelIds", lab);

	std::stringstream ss;	
	write_json(ss, pt);
	//std::cout << ss.str() << std::endl;	

	std::string postURL;
	postURL += "https://www.googleapis.com/gmail/v1/users/" ;
	postURL += userId;
	postURL += "/messages?access_token=" ;
	postURL += accessToken;

	if (DEBUG)
		std::cout << "Main::insertMessage : postURL  " <<  postURL << std::endl;

	RestClient::Response r = RestClient::post(postURL, "application/json", ss.str() );
	//std::cout << r.body << std::endl;	

}

void Main::parseClientJson(std::string& json_file, std::string& client_id, std::string& client_secret)
{
	if (DEBUG )
		std::cout << "Main::parseClientJson " << std::endl;
	boost::property_tree::ptree pt;
	try {
		boost::property_tree::read_json(json_file, pt);
		if ( DEBUG )
			std::cout << "Main::parseClientJson : Client-id " << pt.get<std::string>("installed.client_id") << std::endl;	
		client_id = pt.get<std::string>("installed.client_id"); 
		if (DEBUG )
			std::cout << "Main::parseClientJson : Client-secret " << pt.get<std::string>("installed.client_secret") << std::endl;
		client_secret = pt.get<std::string>("installed.client_secret"); 
	} catch (std::exception& ex ) {
		std::cout << ex.what() << std::endl;
		std::cerr << "Invalid Json provided!. Please regenerate again. Check if json contains fields: client_id, client_secret" << std::endl;
		std::exit(EXIT_FAILURE);
	}

}

void Main::getAccessTokens(boost::property_tree::ptree const& pt, std::map<std::string, std::string>& accessMap )
{
	using boost::property_tree::ptree;
	ptree::const_iterator end = pt.end();
	for (ptree::const_iterator it = pt.begin(); it != end; ++it) {
		//std::cout << it->first << ": " << it->second.get_value<std::string>() << std::endl;
		if ( it->first.compare("access_token") == 0 )
		{
			if (DEBUG)
				std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			accessMap["access_token"] = it->second.get_value<std::string>();	
		}
		if ( it->first.compare("token_type") == 0 )
		{
			if (DEBUG)
				std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			accessMap["token_type"] = it->second.get_value<std::string>();	
		}
		if ( it->first.compare("expires_in") == 0 )
		{
			if (DEBUG)
				std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			accessMap["expires_in"] = it->second.get_value<std::string>();	
		}
		if ( it->first.compare("refresh_token") == 0 )
		{
			if (DEBUG)
				std::cout << it->first << " : " << it->second.get_value<std::string> () << std::endl;
			accessMap["refresh_token"] = it->second.get_value<std::string>();	
		}

		getAccessTokens(it->second, accessMap); 
	}
}


void Main::performOAuth(std::string& client_id, std::string& client_secret, std::string& accessToken, std::string& refreshToken)
{
	if (DEBUG)
		std::cout << "Main::performOAuth " << std::endl;
	
	FILE *in;
	char buff[512];
	std::string buf;

	std::string scope = "https://mail.google.com";

	std::string codeURL, tokenURL;
	std::string auth_code;

	codeURL += "https://accounts.google.com/o/oauth2/auth?client_id=" ;
	codeURL += client_id;
	codeURL += "&scope=";
	codeURL += scope;
	codeURL += "&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob";

	std::cout << "Please visit " << std::endl;
	std::cout << codeURL << std::endl;
	std::cout << "after accepting, enter the code you are given:" << std::endl;

	std::cin >> auth_code;

	tokenURL += "curl -s https://accounts.google.com/o/oauth2/token -d code=";
	tokenURL += auth_code;
	tokenURL += " -d client_id=";
	tokenURL += client_id;
	tokenURL += " -d client_secret=";
	tokenURL += client_secret;
	tokenURL += " -d redirect_uri=urn:ietf:wg:oauth:2.0:oob -d grant_type=authorization_code -H 'Content-Type: application/x-www-form-urlencoded'";

	if (DEBUG )
		std::cout << "Main::performOAuth : tokenURL " << tokenURL << std::endl;
	if(!(in = popen(tokenURL.c_str(), "r"))){
		//return 1;
		std::cerr << "Authentication failed " << std::endl;	
	}

	while(fgets(buff, sizeof(buff), in)!=NULL){
		//cout << buff;
		buf += buff;
	}
	pclose(in);
	std::cout << buf << std::endl;

	std::stringstream json(buf);

	boost::property_tree::ptree pt;
	boost::property_tree::read_json(json, pt);

	std::map<std::string, std::string> accessMap;
	getAccessTokens(pt, accessMap);

	//std::cout << accessMap["access_token"] << std::endl; 
	//std::cout << accessMap["refresh_token"] << std::endl; 

	accessToken = accessMap["access_token"];
	refreshToken = accessMap["refresh_token"];	

}

void Main::validateDates(std::string& dateAfter, std::string& dateBefore)
{
	if (DEBUG )
		std::cout << "Main::validateDates " << std::endl;
	struct tm tm1;
	struct tm tm2;
	if (!strptime(dateAfter.c_str(), "%Y/%m/%d", &tm1))
	{
		std::cerr << "<DateAfter> is invalid" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	if (!strptime(dateBefore.c_str(), "%Y/%m/%d", &tm2))
	{
		std::cerr << "<Date Before> is invalid" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	if ( tm1.tm_year > tm2.tm_year ||
			(tm1.tm_year == tm2.tm_year && tm1.tm_mon > tm2.tm_mon) ||
			(tm1.tm_year == tm2.tm_year && tm1.tm_mon == tm2.tm_mon && tm1.tm_mday >= tm2.tm_mday))
	{
		// After is further away
		std::cerr << "<Date After> is greater than or equal to <Date Before> " << std::endl;
		std::exit(EXIT_FAILURE);	
	}

}

void Main::run()
{
	validateDates(dateAfter, dateBefore);

	// Validate all these parameters!!
	// 
	std::cout << userId  << std::endl;
	std::cout << json_file << std::endl;
	std::cout << dateAfter << std::endl;
	std::cout << dateBefore << std::endl;

	userId = urlencode(userId);
	if (DEBUG)
		std::cout << "Main::run : userId (urlencded) " << userId << std::endl;
	parseClientJson(json_file, client_id, client_secret);
	performOAuth(client_id, client_secret, accessToken, refreshToken);

	try
	{
		std::vector<std::string> messageIds;
		//std::string dateRange = "in%3Ainbox+after%3A2016%2F08%2F01+before%3A2016%2F08%2F03";
		std::string dateFilter;
		dateFilter += "in:inbox after:";
		dateFilter += dateAfter;
		dateFilter += " before:";
		dateFilter += dateBefore;

		//std::string dateRange = urlencode("in:inbox after:2016/08/01 before:2016/08/03"); 
		std::string dateRange = urlencode(dateFilter);
		getMessageIdsInRange(userId, dateRange, accessToken, messageIds);

		//messageIds.erase(messageIds.begin(), messageIds.end());
		//messageIds.push_back("15646477779d4611");

		for(int i = 0; i < messageIds.size(); i++)
		{
			if (DEBUG)
				std::cout << " Main::run: MessageId: " << messageIds[i] << std::endl;

			boost::property_tree::ptree pt;
			//boost::property_tree::read_json("message.json", pt);

			std::vector<std::string> name;
			std::vector<std::string> value;
			std::vector<std::string> data;
			getMessageJson(pt, userId, messageIds[i], accessToken);
			getNameValueData(pt, name, value, data);

			// Bug Fix : Change all 'names' to lower case
			for ( int i = 0; i < name.size(); i++ )
				std::transform(name[i].begin(), name[i].end(), name[i].begin(), ::tolower);
				

			if ( name.size() != value.size() )
			{	
				std::cout << "Json name-value pairs not ordered " << std::endl;
				std::exit(EXIT_FAILURE);
			}
			

			std::string rawJson;
			prepareRawJson(name, value, data, rawJson);

			//std::cout << "RawJson: ############################### " << rawJson << std::endl;

			std::string encodedRawJson;

			CryptoPP::StringSource ss(rawJson, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedRawJson), false));

			// RFC 2822
			replace(encodedRawJson.begin(), encodedRawJson.end(), '+', '-');
			replace(encodedRawJson.begin(), encodedRawJson.end(), '/', '_');

			insertMessage(userId, encodedRawJson,accessToken);
		}


	}
	catch (std::exception const& e)
	{
		std::cerr << e.what() << std::endl;
	} 
}

void Main::init(int nparams, char* params[] )
{
	userId = params[1];
	json_file = params[2];
	dateAfter = params[3];
	dateBefore = params[4];
	if (nparams == 6 && (strcmp(params[5],"-verbose") == 0) )
		DEBUG = 1;
	else
		DEBUG = 0;

}

int main(int argc, char* argv[])
{
	if (argc < 5 || argc > 6 )
	{
		std::cerr << "Usage: " << argv[0] << " <username@gmail.com> " << "<client_secret_json> " << "<DateAfter> " << "<DateBefore> " << "[-verbose] " << std::endl;
		return 1;	
	} 
	else 
	{
		Main * m = new Main();
		m->init(argc, argv);
		m->run();
	
		delete m;	
		return 0;
	}
}
