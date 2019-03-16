from flask import Flask, jsonify
from flask_restful import reqparse, abort, Api, Resource
import sqlite3


class DB:
    def __init__(self):
        self.conn = sqlite3.connect('data.db', check_same_thread=False)

    def get_connection(self):
        return self.conn

    def __del__(self):
        self.conn.close()


class ArticleModel:

    def __init__(self, connection):
        self.connection = connection

    def get(self, article_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM article WHERE id = ?", (str(article_id),))
        row = cursor.fetchone()
        return row

    def get_all(self, user_id=None):
        cursor = self.connection.cursor()
        if user_id:
            cursor.execute("SELECT * FROM article WHERE user_id = ?",
                           (str(user_id)))
        else:
            cursor.execute("SELECT * FROM article")
        rows = cursor.fetchall()
        return rows


class MessageModel:

    def __init__(self, connection):
        self.connection = connection

    def get_last_num(self, from_user_id, to_user_id):
        cursor = self.connection.cursor()
        cursor.execute(
            '''SELECT * FROM message WHERE
             (from_user_id = ? AND to_user_id = ?) OR
              (to_user_id = ? AND from_user_id = ?)
               ORDER BY id DESC LIMIT 100''',
            (str(from_user_id), str(to_user_id), str(from_user_id),
             str(to_user_id)))
        rows = cursor.fetchall()
        return rows

    def validate(self, api_key, from_user_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE api_key = ?", (api_key,))
        row = cursor.fetchone()
        if row and row[0] == int(from_user_id):
            return True
        else:
            return False

    def insert(self, content, from_user_id, to_user_id):
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO Message (text, from_user_id, to_user_id) VALUES (?,?,?)",
            (content, from_user_id, to_user_id))
        cursor.close()
        self.connection.commit()


app = Flask(__name__)
app.config['SECRET_KEY'] = "d0ntknow40u103don1knowm3301"
api = Api(app)

db = DB()


def abort_if_news_not_found(article_id):
    if not ArticleModel(db.get_connection()).get(article_id):
        abort(404, message="News {} not found".format(article_id))


def abort_if_messages_not_found(from_id, to_id):
    if not MessageModel(db.get_connection()).get_last_num(from_id, to_id):
        abort(404,
              message="Messages from {} to {} not found".format(from_id, to_id))


parser_article_group = reqparse.RequestParser()
parser_article_group.add_argument('user_id', required=False)

parser_message_group = reqparse.RequestParser()
parser_message_group.add_argument('from_user_id', required=True)
parser_message_group.add_argument('to_user_id', required=True)
parser_message_group.add_argument('api_key', required=True)
parser_message_group.add_argument('text', required=True)


class Article(Resource):

    def get(self, article_id):
        abort_if_news_not_found(article_id)
        articles = ArticleModel(db.get_connection()).get(article_id)
        return jsonify({'articles': articles})


class Message(Resource):

    def get(self, from_user_id, to_user_id, api_key):
        abort_if_messages_not_found(from_user_id, to_user_id)
        if MessageModel(db.get_connection()).validate(api_key=api_key,
                                                      from_user_id=from_user_id):
            messages = MessageModel(db.get_connection()).get_last_num(
                from_user_id, to_user_id)
        else:
            messages = "Access denied!"
        return jsonify({'messages': messages})


class AddMessage(Resource):

    def post(self):
        args = parser_message_group.parse_args()
        if MessageModel(db.get_connection()).validate(api_key=args['api_key'],
                                                      from_user_id=args[
                                                          'from_user_id']):
            MessageModel(db.get_connection()).insert(args['text'],
                                                     args['from_user_id'],
                                                     args['to_user_id'])
            status = "OK"
        else:
            status = "permissions denied"
        return jsonify({"status": status})


class Articles(Resource):

    def get(self):
        args = parser_article_group.parse_args()
        if not args.get("user_id"):
            articles = ArticleModel(db.get_connection()).get_all()
        else:
            articles = ArticleModel(db.get_connection()).get_all(
                args["user_id"])
        return jsonify({"articles": articles})


api.add_resource(Message, '/messages/<api_key>/<from_user_id>/<to_user_id>')
api.add_resource(AddMessage, '/messages/add')
api.add_resource(Articles, '/articles')
api.add_resource(Article, '/articles/<int:article_id>')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
