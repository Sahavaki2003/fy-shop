function authority(role) {
    return (req,rep,done) => {
        if(req.user&&req.user.role === role) {
            done();
        } else {
            rep.redirect(`/login?err=unAthority&url=${req.url}&role=${role}`);
        }
    }
}
module.exports = authority;