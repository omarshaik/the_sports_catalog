from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

admin = User(name="Omar Shaik", email="omshaik10@gmail.com")
session.add(admin)
session.commit()

category = Category(user_id=1, name="Baseball")
session.add(category)
session.commit()

item = Item(user_id=1, name="Baseball Bat", description="The tool used to hit baseballs. Can be customized and made from many different kinds of wood.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Baseball", description="The ball with which baseball is played.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Baseball Glove", description="The tool used to catch baseballs.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Hockey")
session.add(category)
session.commit()

item = Item(user_id=1, name="Hockey Stick", description="The tool used to hit hockey pucks. Also a term for insane growth.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Hockey Puck", description="A black, disk-like object. It is like a snitch in Quidditch.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Basketball")
session.add(category)
session.commit()

item = Item(user_id=1, name="Basketball", description="An orange, spherical object. It is bounced, often in creative and treacherous ways.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Basketball Hoop", description="The object in which the basketball is thrown.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Football")
session.add(category)
session.commit()

item = Item(user_id=1, name="Football", description="A brown, oddly-shaped object. It is thrown in a spiral.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Helmet", description="The object that fails to prevent concussions. It is worn on the head.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Futbol (Soccer)")
session.add(category)
session.commit()

item = Item(user_id=1, name="Soccer Ball", description="A white and black, spherical object. It is kicked around and at people, most often the goalie.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Volleyball")
session.add(category)
session.commit()

item = Item(user_id=1, name="Volleyball", description="A spherical object. It is slapped around by athletes. Often mistaken for a soccer ball.", category=category)
session.add(item)
session.commit()

category = Category(user_id=1, name="Golf")
session.add(category)
session.commit()

item = Item(user_id=1, name="Golf Ball", description="A spherical object. It is hit impressively long distances. May look like a miniature volleyball to the untrained eye.", category=category)
session.add(item)
session.commit()

item = Item(user_id=1, name="Golf Club", description="A club that meets to play golf, usually on the weekends.", category=category)
session.add(item)
session.commit()



