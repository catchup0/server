exports.renderProfile = (req, res, next) => {
    res.render('profile', {title: '내 정보 - NodeBird'});
};
exports.renderJoin = (req, res, next) => {
    res.render('join', {title: '회원가입 - NodeBire'});
};
exports.renderMain = (req, res, next) => {
    res.render('main',{
        title: 'NodeBird',
        twits: [], //트위터 게시물

    });
};

// 라우터 -> 컨트롤러 -> 서비스(요청, 응답 모름) 순으로 호출