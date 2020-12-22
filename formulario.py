from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField,SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from wtforms.validators import Length

class Contactenos(FlaskForm):
    nombre = StringField('Nombre',validators=[ DataRequired(message="Este campo es obligatorio"),
                                               Length(max=30)])
    correo = EmailField('Correo',validators=[ DataRequired(message="Este campo es obligatorio")])
    mensaje = StringField('Mensaje',validators=[ DataRequired(message="Este campo es obligatorio")])
    enviar = SubmitField('Enviar mensaje')


def convertToBinaryData(filename):
    #Convert digital data to binary format
    with open(filename, 'rb') as file:
        blobData = file.read()
    return blobData


def writeTofile(data, filename):
    # Convert binary data to proper format and write it on Hard Disk
    with open(filename, 'wb') as file:
        file.write(data)
    print("Stored blob data into: ", filename, "\n")