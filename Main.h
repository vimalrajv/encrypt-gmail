#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <cassert>
#include <ctime>
#include <exception>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <string>
#include "base64.h"
#include "modes.h"
#include "aes.h"
#include "hex.h"
#include "filters.h"
#include "restclient-cpp/restclient.h"
#include "restclient-cpp/connection.h"

class Main
{
	private:
 
	int DEBUG; 
	std::string userId;
	std::string json_file;
	std::string dateAfter;
	std::string dateBefore;
	std::string client_id;
	std::string client_secret;
	std::string accessToken;
	std::string refreshToken;
	std::string dateRange ;

	//std::vector<std::string> name;
	//std::vector<std::string> value;
	//std::vector<std::string> data;
	//std::vector<std::string> messageIds;

	//std::string rawJson;
	//std::string encodedRawJson;

	void getMessageIds(boost::property_tree::ptree const& pt, std::vector<std::string>& messageIds);
	void getNameValueData(boost::property_tree::ptree const& pt, std::vector<std::string>& name, std::vector<std::string>& value, std::vector<std::string>& data );
	std::string AESEncryptData(std::string& plainText);
	void prepareRawJson(std::vector<std::string>& name, std::vector<std::string>& value, std::vector<std::string>& data, std::string& rawJson );
	void getMessageIdsFromJson(boost::property_tree::ptree const& pt, std::vector<std::string>& messageIds);
	void getMessageIdsInRange(std::string& userId, std::string& dateRange, std::string& accessToken, std::vector<std::string>& messageIds);
	std::string urlencode(const std::string &s);
	void getMessageJson(boost::property_tree::ptree& pt, std::string& userId, std::string& messageId, std::string& accessToken);
	void insertMessage(std::string& userId, std::string& base64Message, std::string& accessToken);
	void parseClientJson(std::string& json_file, std::string& client_id, std::string& client_secret);
	void getAccessTokens(boost::property_tree::ptree const& pt, std::map<std::string, std::string>& accessMap );
	void performOAuth(std::string& client_id, std::string& client_secret, std::string& accessToken, std::string& refreshToken);
	void validateDates(std::string& dateAfter, std::string& dateBefore);

	public:

	void init(int n, char *params[] );
	void run();
};
