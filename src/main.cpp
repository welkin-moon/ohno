#include "policy.hpp"
#include <iostream>
#include <string>
#include <vector>
using namespace ohno;
int main() {
    const std::string game_hash(64, 'a');
    std::vector<Rule> rules{{"example-web",Kind::Website,"game.example",true},
                            {"example-game",Kind::Application,game_hash,false},
                            {"local-html",Kind::LocalHtml,"*",false}};
    std::vector<Request> sample{{Kind::Website,"pc-01","student-01","play.game.example"},
        {Kind::Application,"pc-01","student-01",game_hash},
        {Kind::Network,"pc-01","student-01",std::string(64,'b'),Origin::Downloaded},
        {Kind::Network,"pc-01","student-01",std::string(64,'c'),Origin::Unknown},
        {Kind::LocalHtml,"pc-01","student-01","local-resource-1"}};
    std::cout << "OHNO POLICY SIMULATION ONLY - does not enforce system settings\n";
    for (const auto& request : sample) {
        auto d = evaluate(request, rules, {}, 1000);
        std::cout << to_string(d.action) << " | " << d.reason << " | " << d.rule_id << "\n";
    }
}
