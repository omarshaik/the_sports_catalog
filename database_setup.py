from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Category(Base):
	__tablename__ = 'category'

	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=false)

	@property
	def serialize(self):
	    return {
	    	'name': self.name,
	    	'id': self.id,
	    }

class Item(Base):
	__tablename__ = 'item'

	name = Column(String(80), nullable=false)
	id = Column(Inte, primary_key=True)
	description = Column(String(250))
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category)

	@property
	def seralize(self):
	    return {
	    	'name': self.name,
	    	'description': self.description,
	    	'id': self.id,
	    }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
	