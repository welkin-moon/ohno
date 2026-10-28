#include "policy.hpp"
#include <cassert>
#include <iostream>
using namespace ohno;
int main() {
    const std::string a(64,'a'), b(64,'b');
    const std::vector<Rule> rules{{"web",Kind::Website,"game.example",true},
      {"game",Kind::Application,a,false}, {"html",Kind::LocalHtml,"*",false}};
    auto eval = [&](Request r, std::vector<Grant> g = {}, std::int64_t now=100) {return evaluate(r,rules,g,now).action;};
    assert(eval({Kind::Website,"pc","student","game.example"}) == Action::RequestApproval);
    assert(eval({Kind::Website,"pc","student","sub.game.example"}) == Action::RequestApproval);
    assert(eval({Kind::Website,"pc","student","notgame.example"}) == Action::Allow);
    assert(eval({Kind::Website,"pc","student","GAME.example"}) == Action::Block);
    assert(eval({Kind::Website,"pc","student","game.example."}) == Action::Block);
    assert(eval({Kind::Application,"pc","student",a}) == Action::RequestApproval);
    assert(eval({Kind::Application,"pc","student",b}) == Action::Allow);
    assert(eval({Kind::Application,"pc","student","bad"}) == Action::Block);
    assert(eval({Kind::Network,"pc","student",b,Origin::Downloaded}) == Action::RequestApproval);
    assert(eval({Kind::Network,"pc","student",b,Origin::Removable}) == Action::RequestApproval);
    assert(eval({Kind::Network,"pc","student",b,Origin::Unknown}) == Action::RequestApproval);
    assert(eval({Kind::Network,"pc","student",b,Origin::Managed}) == Action::Allow);
    assert(eval({Kind::LocalHtml,"pc","student","file-1"}) == Action::RequestApproval);
    Request r{Kind::Application,"pc","student",a};
    Grant g{Kind::Application,"pc","student",a,101};
    assert(eval(r,{g},100)==Action::Allow);
    assert(eval(r,{g},101)==Action::RequestApproval);
    g.user="other"; assert(eval(r,{g})==Action::RequestApproval);
    g.user="student"; g.machine="other"; assert(eval(r,{g})==Action::RequestApproval);
    g.machine="pc"; g.object=b; assert(eval(r,{g})==Action::RequestApproval);
    g.object=a; g.kind=Kind::Network; assert(eval(r,{g})==Action::RequestApproval);
    r.user=""; assert(eval(r,{})==Action::Block);
    std::cout << "policy tests passed\n";
}
