import mysql.connector as mc
import sys
import settings


# Wrapper class for database
class Db:
    def __init__(self):
        try:
            self.__connection = mc.connect(host=settings.HOST,
                                            user=settings.USER,
                                            password=settings.PASSWD,
                                            db=settings.DB)
        except mc.Error as e:
            print("Error %d: %s" % (e.args[0], e.args[1]))
            sys.exit(1)

        self.__cursor = self.__connection.cursor()

    def execute(self, sql, values):
        self.__cursor.execute(sql, values)
        return self.__cursor.fetchall()

    def commit(self):
        self.__connection.commit()              # actually executes SQL command 
                                                # (required after INSERT, UPDATE etc.)

    def __del__(self):                          # destructor closes db connection
        self.__cursor.close()
        self.__connection.close()

if __name__ == '__main__':
    db1 = Db()
    print(db1.execute("SELECT * FROM tblUser"))
    del db1
