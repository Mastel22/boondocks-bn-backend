import chaiHttp from 'chai-http';
import { use, request, should } from 'chai';
import app from '../app';
import db from '../models';
import tripsData from './mock-data/trips-data';
import Hash from '../utils/hash';
import tokenizer from '../utils/jwt';
import { roomfactory, hotelfactory, locationfactory } from './scripts/factories';
import truncate from './scripts/truncate';

should();
use(chaiHttp);

const prefix = '/api/v1';

describe('/booking Accomodation booking', () => {
  let token;
  let travelAdmin;
  let supplierToken;
  before(async () => {
    await truncate();
    await locationfactory({ id: 1, city: 'Kigali', country: 'Rwanda' });
    await hotelfactory(tripsData.hotels[0]);
    await roomfactory(tripsData.rooms[0]);
    await roomfactory(tripsData.rooms[3]);
    await roomfactory(tripsData.rooms[2]);

    await db.user.create({
      id: 1,
      firstName: 'John',
      lastName: 'McCain',
      password: Hash.generateSync('1234567e'),
      email: 'john@mccain.com'
    });

    await hotelfactory({
      id: 10,
      locationId: 1,
      name: 'Marriot',
      image: 'image.png',
      description: 'hello world',
      services: 'Catering',
      userId: 1,
    });

    token = await tokenizer.signToken({
      id: 1,
      email: 'john@mccain.com',
      isVerified: 1
    });

    await db.user.create({
      id: 65,
      firstName: 'John',
      lastName: 'McCain',
      password: Hash.generateSync('1234567e'),
      email: 'john@mccain2.com',
      role: 'travel_administrator'
    });

    travelAdmin = await tokenizer.signToken({
      id: 1,
      email: 'john@mccain2.com',
      isVerified: 1,
      role: 'travel_administrator'
    });

    supplierToken = await tokenizer.signToken({
      id: 1,
      email: 'john@mccain2.com',
      isVerified: 1,
      role: 'suppliers'
    });
  });

  it('POST /booking - user should be able to book an accomodation', (done) => {
    request(app)
      .post(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .send(tripsData.booking[0])
      .end((err, res) => {
        const { data } = res.body;
        res.status.should.be.eql(201);
        data.should.be.an('object');
        done();
      });
  });

  it('POST /booking - Arrival date must not be the day in past', (done) => {
    request(app)
      .post(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .send(tripsData.booking[1])
      .end((err, res) => {
        res.status.should.be.eql(400);
        done();
      });
  });

  it('POST /booking - leaving date must be today or in future', (done) => {
    request(app)
      .post(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .send(tripsData.booking[2])
      .end((err, res) => {
        res.status.should.be.eql(400);
        done();
      });
  });

  it('POST /booking - Should not book unregistered rooms', (done) => {
    request(app)
      .post(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .send(tripsData.booking[3])
      .end((err, res) => {
        res.status.should.be.eql(409);
        done();
      });
  });

  it('POST /booking - Should not book when there some unregistered rooms', (done) => {
    request(app)
      .post(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .send(tripsData.booking[4])
      .end((err, res) => {
        res.status.should.be.eql(409);
        done();
      });
  });

  it('GET /booking - Should get all booking for travel admin', (done) => {
    request(app)
      .get(`${prefix}/booking`)
      .set('Authorization', `Bearer ${travelAdmin}`)
      .end((err, res) => {
        res.status.should.be.eql(200);
        done();
      });
  });

  it('GET /booking - Should get all booking for user', (done) => {
    request(app)
      .get(`${prefix}/booking`)
      .set('Authorization', `Bearer ${token}`)
      .end((err, res) => {
        res.status.should.be.eql(200);
        done();
      });
  });

  it('GET /booking - Should get all booking for supplier', (done) => {
    request(app)
      .get(`${prefix}/booking`)
      .set('Authorization', `Bearer ${supplierToken}`)
      .end((err, res) => {
        res.status.should.be.eql(200);
        done();
      });
  });
});
