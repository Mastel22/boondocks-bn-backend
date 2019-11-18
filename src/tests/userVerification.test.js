import chai from 'chai';
import chaiHttp from 'chai-http';
import { describe, it } from 'mocha';
import app from '../app';
import userData from './mock-data/verification.data';
import truncate from './scripts/truncate';
import db from '../models';

chai.use(chaiHttp);
chai.should();
let tokenTest;

describe('verify users` emails', () => {
  describe('verification email', () => {
    before(async () => {
      await truncate();
    });
    before((done) => {
      chai
        .request(app)
        .post('/api/v1/auth/signup')
        .send(userData.user)
        .end((err, res) => {
          tokenTest = res.body.data.token;
          done();
        });
    });

    it('verify user email successfully', (done) => {
      chai
        .request(app)
        .get(`/api/v1/auth/verification?token=${tokenTest}`)
        .end((err, res) => {
          res.should.have.status(200);
          res.body.should.be.a('object');
          res.body.message.should.equal('Email has been verified successfully, please proceed to log in');
          if (err) return done();
          done();
        });
    });

    it('Should not verify twice', (done) => {
      chai
        .request(app)
        .get(`/api/v1/auth/verification?token=${tokenTest}`)
        .end((err, res) => {
          res.should.have.status(409);
          res.body.should.be.a('object');
          res.body.message.should.equal('you are already verified, please login to proceed');
          if (err) return done();
          done();
        });
    });

    it('Should not verify with invalid token', (done) => {
      chai
        .request(app)
        .get('/api/v1/auth/verification?token=123248488')
        .end((err, res) => {
          res.should.have.status(401);
          res.body.should.be.a('object');
          res.body.message.should.equal('invalid token, regenerate another token using the link in your verification email');
          if (err) return done();
          done();
        });
    });
  });
  describe('verification email', () => {
    before(async () => {
      await truncate();
      await db.user.create(userData.user1);
    });
    it('resend verification email successfully', (done) => {
      chai
        .request(app)
        .get(`/api/v1/auth/reverifyUser?email=${userData.user1.email}`)
        .end((err, res) => {
          res.should.have.status(200);
          res.body.should.be.a('object');
          res.body.message.should.equal('Email has been resent successfully, please check your mail');
          if (err) return done();
          done();
        });
    });
    it('verifications\' email does not exist', (done) => {
      chai
        .request(app)
        .get('/api/v1/auth/reverifyUser?email=test@test.com')
        .end((err, res) => {
          res.should.have.status(404);
          res.body.should.be.a('object');
          res.body.message.should.equal('No account with such email exists, please sign up');
          if (err) return done();
          done();
        });
    });
  });
});
