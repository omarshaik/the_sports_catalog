from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item

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

category = Category(name="Baseball")
session.add(category)
session.commit()

item = Item(name="Baseball Bat", description="The tool used to hit baseballs. Can be customized and made from many different kinds of wood.", category=category)
session.add(item)
session.commit()

item = Item(name="Baseball", description="The ball with which baseball is played.", category=category)
session.add(item)
session.commit()

item = Item(name="Baseball Glove", description="The tool used to catch baseballs.", category=category)
session.add(item)
session.commit()

category = Category(name="Hockey")
session.add(category)
session.commit()

item = Item(name="Hockey Stick", description="The tool used to hit hockey pucks. Also a term for insane growth.", category=category)
session.add(item)
session.commit()

item = Item(name="Hockey Puck", description="A black, disk-like object. It is like a snitch in Quidditch.", category=category)
session.add(item)
session.commit()

category = Category(name="Basketball")
session.add(category)
session.commit()

item = Item(name="Basketball", description="An orange, spherical object. It is bounced, often in creative and treacherous ways.", category=category)
session.add(item)
session.commit()

item = Item(name="Basketball Hoop", description="The object in which the basketball is thrown.", category=category)
session.add(item)
session.commit()



