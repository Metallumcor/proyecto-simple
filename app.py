

from flask import Flask, render_template, request, flash, jsonify, redirect, session, g, url_for, send_file, make_response
from formulario import Contactenos, convertToBinaryData, writeTofile
from db import get_db, close_db
from message import mensajes
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


from OpenSSL.crypto import FILETYPE_PEM

import utils
import os  # Agregue la libreria os
import yagmail as yagmail
import functools

app = Flask(__name__)
# Ocurrio un eror: The session is unavailable because no secret key was set.
# Set the secret_key on the application to something unique and secret.
app.secret_key = os.urandom(24)
# Esta linea nos va a permitir realizar las peticiones cliente servidor de forma segura por medio de una
# contraseña cifrada, en este caso mande una contraseña que viniera del Sistema operativo de manera aleatoria
# de 24 caracteres

# DEIZY src --->'https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/'
UPLOAD_FOLDER = './resources'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')  # debe ir a /login/ para que funcione el metodo post
def home():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if g.user:  # DAVID
            return redirect('/logout')  # DAVID
        if request.method == 'POST':
            close_db()  # DAVID
            db = get_db()
            username = request.form['usuario']
            password = request.form['password']
            error = None

            if not username:
                error = "Debes ingresar el usuario"
                flash(error)
                return render_template('login.html')
            if not password:
                error = "Contraseña es requerida"
                flash(error)
                return render_template('login.html')

            print("usuario: " + username + " clave:" + password)

            user = db.execute('SELECT * FROM usuarios WHERE usuario=? ',
                              (username,)).fetchone()

            if user is None:
                error = 'Usuario o contraseña inválidos'
                flash(error)
                return render_template('login.html')
            elif check_password_hash(user[3], password):
                session.clear()  # DAVID - empieza
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                if session.get('role') == "Administrador":
                    return redirect('/admin')
                return redirect('/employee')  # DAVID - termina
            else:
                error = 'Usuario o contraseña inválidos'
                flash(error)
                return render_template('login.html')

        return render_template('login.html')
    except TypeError as e:
        print("Ocurrio un error:", e)
        return render_template('login.html')


# Métodos de Login - DAVID
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect("/login")
        return view(**kwargs)

    return wrapped_view


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/login")


@app.before_request
def load_logged_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM usuarios WHERE id=?', (user_id,)
        ).fetchone()
        close_db()


@app.route('/error')
def privilege_error():
    return render_template('error.html')


# Fin de métodos


@app.route('/admin')
@login_required  # DAVID
def admin():
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    return render_template('principalAdmin.html')


@app.route('/employee', methods=('GET', 'POST'))
@login_required  # DAVID
def employee():
    try:
        if request.method == 'GET':
            db = get_db()
            product_list = db.execute('SELECT * FROM productos;').fetchall()
            #print(product_list)
            return render_template('principalEmpleado.html', productos=product_list)
        else:  # BUSQUEDA - INICIO
            close_db()
            db = get_db()
            busqueda = request.form['search']
            if busqueda is None:
                product_list = db.execute('SELECT * FROM productos;').fetchall()
            else:
                query = "SELECT * FROM productos WHERE nombre LIKE '%{0}%';".format(busqueda)
                product_list = db.execute(query).fetchall()
            #print(product_list)
            return render_template('principalEmpleado.html', productos=product_list)
        # BUSQUEDA - FIN

    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalEmpleado.html')

    # return render_template('principalEmpleado.html')


@app.route('/employee/editProduct', methods=('GET', 'POST'))
@app.route('/employee/editProduct/<int:idPro>', methods=('GET', 'POST'))
@login_required  # DAVID
def editProduct(idPro=None):
    try:
        if request.method == 'POST':
            prod_quantity = request.form['productQuantity']
            db = get_db()
            print(idPro)
            if db.execute('SELECT id FROM productos WHERE referencia=?', (idPro,)).fetchone() is None:
                print("pasa por aqui")
                error = 'El producto no existe'.format(idPro)
                flash(error)
                product_list = db.execute('SELECT * FROM productos;').fetchall()
                return render_template('principalEmpleado.html', productos=product_list)

            db.execute('UPDATE productos SET cantidad=?  WHERE referencia =?',
                       (prod_quantity, idPro))
            db.commit()

            product_list = db.execute('SELECT * FROM productos;').fetchall()
            return render_template('principalEmpleado.html', productos=product_list)

        if request.method == 'GET' and idPro:
            db = get_db()
            product = db.execute('SELECT * FROM productos WHERE id=?',
                                 (idPro,)).fetchone()
            return render_template('editarCantidadProducto.html', product=product)

        return render_template('editarCantidadProducto.html', product=[(0, 0, 0, 0)])
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('editarCantidadProducto.html', product=[(0, 0, 0, 0)])


@app.route('/admin/product', methods=('GET', 'POST'))
@login_required  # DAVID
def product():
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'GET':
            db = get_db()
            product_list = db.execute('SELECT * FROM productos;').fetchall()
            #print(product_list)
            return render_template('producto.html', productos=product_list)
        else:  # BUSQUEDA - INICIO
            close_db()
            db = get_db()
            busqueda = request.form['search']
            if busqueda is None:
                product_list = db.execute('SELECT * FROM productos;').fetchall()
            else:
                query = "SELECT * FROM productos WHERE nombre LIKE '%{0}%';".format(busqueda)
                product_list = db.execute(query).fetchall()
            #print(product_list)
            return render_template('producto.html', productos=product_list)
        # BUSQUEDA - FIN
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalAdmin.html')

    # return render_template('producto.html')


@app.route('/admin/users', methods=('GET', 'POST'))  # DEIZY
@login_required  # DAVID
def users():
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'GET':
            db = get_db()
            users_list = db.execute('SELECT * FROM usuarios;').fetchall()
            #print(users_list)
            return render_template('usuarios.html', users=users_list)
        else:  # BUSQUEDA - INICIO
            close_db()
            db = get_db()
            busqueda = request.form['search']
            if busqueda is None:
                users_list = db.execute('SELECT * FROM usuarios;').fetchall()
            else:
                query = "SELECT * FROM usuarios WHERE usuario LIKE '%{0}%';".format(busqueda)
                users_list = db.execute(query).fetchall()
            #print(product_list)
            return render_template('usuarios.html', users=users_list)
        # BUSQUEDA - FIN

    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalAdmin.html')  # DEIZY

# MODIFICAR USUARIO DEIZY

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/admin/users/edit-employee/', methods=('GET', 'POST'))
@app.route('/admin/users/edit-employee/<int:idUser>', methods=('GET', 'POST'))
@login_required  # DAVID
def edit_employee(idUser=None):
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'POST':
            username = request.form['usuario']
            password = request.form['password']
            email = request.form['email']
            tipo = request.form['tipo']
            error = None
            close_db()
            db = get_db()

            if not utils.isUsernameValid(username):
                error = "El usuario debe ser alfanumerico"
                flash(error)
                user = db.execute('SELECT * FROM usuarios WHERE id=?', (idUser,)).fetchone()
                return render_template('editarUsuario.html', user=user)

            if not utils.isEmailValid(email):
                error = 'Correo inválido'
                flash(error)
                user = db.execute('SELECT * FROM usuarios WHERE id=?', (idUser,)).fetchone()
                return render_template('editarUsuario.html', user=user)

            if not utils.isPasswordValid(password):
                error = 'La contraseña debe tener por los menos una mayúcscula y una mínuscula y 8 caracteres'
                flash(error)
                user = db.execute('SELECT * FROM usuarios WHERE id=?', (idUser,)).fetchone()
                return render_template('editarUsuario.html', user=user)

            if db.execute('SELECT id FROM usuarios WHERE id=?', (idUser,)).fetchone() is None:
                error = 'El usuario no existe'.format(idUser)
                flash(error)
                user = db.execute('SELECT * FROM usuarios WHERE id=?', (idUser,)).fetchone()
                return render_template('editarUsuario.html', user=user)

            hashpass = generate_password_hash(password)

            db.execute('UPDATE usuarios SET usuario=?, correo=?, contraseña=?, tipo=? WHERE id=?',
                       (username, email, hashpass, tipo, idUser))

            db.commit()
            # serverEmail = yagmail.SMTP('misiontic.2020.grupod@gmail.com', 'Karen.1234')
            #
            # serverEmail.send(to=email, subject='Actualizacion de datos',
            #                  contents='Usuario, sus datos han sido actualizados')
            flash('Revisa tu correo para verificar los datos actualizados')
            print('Empleado modificado')
            # DEIZY
            # IMAGE
            # check if the post request has the file part
            if 'file' not in request.files:
                print('No file part')
            else:
                file = request.files['file']
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                if file.filename == '':
                    print('No selected file')
                    users_list = db.execute('SELECT * FROM usuarios;').fetchall()
                    return render_template('usuarios.html', users=users_list)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    print(filename.split('.'))
                    ext_photo = filename.split('.')
                    ext_photo = ext_photo[1]
                    name_photo = username + '.' + ext_photo
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    route_photo = 'resources/'+filename
                    user_photo = convertToBinaryData(route_photo)

                    db.execute('UPDATE usuarios SET foto=?, foto_name=? WHERE id=?',
                               (user_photo, name_photo, idUser))

                    db.commit()

                    # crear imagen en static/fotos
                    writeTofile(user_photo, 'static/images/fotos/' + name_photo)
                else:
                    flash('extension no permitida')
                    user = db.execute('SELECT * FROM usuarios WHERE id=?', (idUser,)).fetchone()
                    return render_template('editarUsuario.html', user=user)

            users_list = db.execute('SELECT * FROM usuarios;').fetchall()
            return render_template('usuarios.html', users=users_list)


        if request.method == 'GET' and idUser:
            db = get_db()
            user = db.execute('SELECT * FROM usuarios WHERE id=?',
                              (idUser,)).fetchone()
            # print(user)
            return render_template('editarUsuario.html', user=user)
        return render_template('editarUsuario.html')
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('editarUsuario.html')


@app.route('/admin/users/add-employee', methods=('GET', 'POST'))
@login_required  # DAVID
def add_employee():
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'POST':
            username = request.form['usuario']
            password = request.form['password']
            email = request.form['email']
            tipo = request.form['tipo']
            error = None

            close_db()
            db = get_db()

            if not utils.isUsernameValid(username):
                error = "El usuario debe ser alfanumerico"
                flash(error)
                return render_template('agregarUsuario.html')

            if not utils.isEmailValid(email):
                error = 'Correo inválido'
                flash(error)
                return render_template('agregarUsuario.html')

            if not utils.isPasswordValid(password):
                error = 'La contraseña debe tener por los menos una mayúcscula y una mínuscula y 8 caracteres'
                flash(error)
                return render_template('agregarUsuario.html')

            if db.execute('SELECT id FROM usuarios WHERE correo=?', (email,)).fetchone() is not None:
                error = 'El correo ya existe'.format(email)
                flash(error)
                return render_template('agregarUsuario.html')

            hashpass = generate_password_hash(password)

            db.execute('INSERT INTO usuarios (usuario,correo,contraseña,tipo) VALUES (?,?,?,?)',
                       (username, email, hashpass, tipo))

            db.commit()
            serverEmail = yagmail.SMTP('misiontic.2020.grupod@gmail.com', 'Karen.1234')

            serverEmail.send(to=email, subject='Activa tu cuenta',
                             contents='Bienvenido, usa este link para activar tu cuenta')
            flash('Revisa tu correo para activar tu cuenta')
            # DEIZY
            # IMAGE
            # check if the post request has the file part
            if 'file' not in request.files:
                print('No file part')
            else:
                file = request.files['file']
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                if file.filename == '':
                    print('No selected file')
                    users_list = db.execute('SELECT * FROM usuarios;').fetchall()
                    return render_template('usuarios.html', users=users_list)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    print(filename.split('.'))
                    ext_photo = filename.split('.')
                    ext_photo = ext_photo[1]
                    name_photo = username + '.' + ext_photo
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    route_photo = 'resources/' + filename
                    user_photo = convertToBinaryData(route_photo)

                    db.execute('UPDATE usuarios SET foto=?, foto_name=? WHERE usuario=?',
                               (user_photo, name_photo, username))

                    db.commit()

                    # crear imagen en static/fotos
                    writeTofile(user_photo, 'static/images/fotos/' + name_photo)
                else:
                    flash('extension no permitida')
                    return render_template('agregarUsuario.html')

            users_list = db.execute('SELECT * FROM usuarios;').fetchall()
            return render_template('usuarios.html', users=users_list)

        return render_template('agregarUsuario.html')
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('agregarUsuario.html')


@app.route('/admin/user/del/', methods=('GET', 'POST'))
@app.route('/admin/user/del/<int:idUser>', methods=('GET', 'POST'))
@login_required  # DAVID
def delete_employee(idUser=None):
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'POST' and idUser:
            db = get_db()
            db.execute('DELETE FROM usuarios WHERE id=?',
                       (idUser,)).fetchone()
            db.commit()

            users_list = db.execute('SELECT * FROM usuarios;').fetchall()
            return render_template('usuarios.html', users=users_list)

        return render_template('principalAdmin.html')

    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalAdmin.html')


@app.route('/admin/product/add', methods=('GET', 'POST'))
@login_required  # DAVID
def add_product():
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'POST':
            prod_id = request.form['productId']
            prod_name = request.form['productName']
            prod_quantity = request.form['productQuantity']
            prod_description = request.form['productDescription']
            # prod_image = request.form['Image']

            db = get_db()

            if db.execute('SELECT id FROM productos WHERE referencia=?', (prod_id,)).fetchone() is not None:
                error = 'El producto ya existe'.format(prod_id)
                flash(error)
                return render_template('agregarProducto.html')

            db.execute('INSERT INTO productos (referencia,nombre,cantidad,descripcion) VALUES (?,?,?,?)',
                       (prod_id, prod_name, prod_quantity, prod_description))

            db.commit()
            flash('Producto Creado!')
            # DEIZY
            # IMAGE
            # check if the post request has the file part
            if 'file' not in request.files:
                print('No file part')
            else:
                file = request.files['file']
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                if file.filename == '':
                    print('No selected file')
                    product_list = db.execute('SELECT * FROM productos;').fetchall()
                    return render_template('producto.html', products=product_list)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    print(filename.split('.'))
                    ext_photo = filename.split('.')
                    ext_photo = ext_photo[1]
                    name_photo = prod_name + '.' + ext_photo
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    route_photo = 'resources/' + filename
                    user_photo = convertToBinaryData(route_photo)

                    db.execute('UPDATE productos SET foto=?, foto_name=? WHERE referencia=?',
                               (user_photo, name_photo, prod_id))

                    db.commit()

                    # crear imagen en static/fotos
                    writeTofile(user_photo, 'static/images/productos/' + name_photo)
                else:
                    flash('extension no permitida')
                    return render_template('agregarProducto.html')
            product_list = db.execute('SELECT * FROM productos;').fetchall()
            return render_template('producto.html', productos=product_list)
        return render_template('agregarProducto.html')
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('agregarProducto.html')


@app.route('/admin/product/mod/', methods=('GET', 'POST'))
@app.route('/admin/product/mod/<int:idPro>', methods=('GET', 'POST'))
@login_required  # DAVID
def mod_product(idPro=None):
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    print("pasa por aqui")
    try:
        if request.method == 'POST':
            prod_id = request.form['productId']
            prod_name = request.form['productName']
            prod_quantity = request.form['productQuantity']
            prod_description = request.form['productDescription']
            # prod_mod_image = request.form['Image']

            db = get_db()

            if db.execute('SELECT id FROM productos WHERE id=?', (idPro,)).fetchone() is None:
                error = 'El producto NO existe'.format(idPro)
                flash(error)
                return render_template('modificarProducto.html')
            print("Producto Modificado")
            db.execute('UPDATE productos SET referencia=?, nombre=?, cantidad=?, descripcion=?  WHERE id=?',
                       (prod_id, prod_name, prod_quantity, prod_description, idPro))

            db.commit()
            # DEIZY
            # IMAGE
            # check if the post request has the file part
            if 'file' not in request.files:
                print('No file part')
            else:
                file = request.files['file']
                # If the user does not select a file, the browser submits an
                # empty file without a filename.
                if file.filename == '':
                    print('No selected file')
                    product_list = db.execute('SELECT * FROM productos;').fetchall()
                    return render_template('producto.html', products=product_list)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    print(filename.split('.'))
                    ext_photo = filename.split('.')
                    ext_photo = ext_photo[1]
                    name_photo = prod_name + '.' + ext_photo
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    route_photo = 'resources/' + filename
                    user_photo = convertToBinaryData(route_photo)

                    db.execute('UPDATE productos SET foto=?, foto_name=? WHERE id=?',
                               (user_photo, name_photo, idPro))

                    db.commit()

                    # crear imagen en static/fotos
                    writeTofile(user_photo, 'static/images/productos/' + name_photo)
                else:
                    flash('extension no permitida')
                    product = db.execute('SELECT * FROM productos WHERE id=?', (idPro,)).fetchone()
                    return render_template('modificarProducto.html', product=product)
            product_list = db.execute('SELECT * FROM productos;').fetchall()
            return render_template('producto.html', productos=product_list)

        if request.method == 'GET' and idPro:
            db = get_db()
            product = db.execute('SELECT * FROM productos WHERE id=?',
                                 (idPro,)).fetchone()
            #print(product)
            return render_template('modificarProducto.html', product=product)

        return render_template('principalAdmin.html')
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalAdmin.html')


@app.route('/admin/product/del/', methods=('GET', 'POST'))
@app.route('/admin/product/del/<int:idPro>', methods=('GET', 'POST'))
@login_required  # DAVID
def delete_product(idPro=None):
    if g.user[4] != "Administrador":
        print(g.user[4])
        return redirect('/error')
    try:
        if request.method == 'POST' and idPro:
            db = get_db()
            db.execute('DELETE FROM productos WHERE referencia=?',
                       (idPro,)).fetchone()
            db.commit()

            product_list = db.execute('SELECT * FROM productos;').fetchall()
            return render_template('producto.html', productos=product_list)

        return render_template('principalAdmin.html')

    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('principalAdmin.html')


@app.route('/employee/product-id')  # QUIZAS QUITAR ESTO
@login_required  # DAVID
def inventory():
    return render_template('editarCantidadProducto.html')


@app.route('/forgot', methods=('POST', 'GET'))
#@login_required  # DAVID
def forgot():
    try:
        if g.user:  # DAVID
            return redirect('/logout')  # DAVID
        if request.method == 'POST':
            email = request.form['email']
            error = None

            if not utils.isEmailValid(email):
                error = 'Correo inválido'
                flash(error)
                return render_template('forgot.html')

            serverEmail = yagmail.SMTP('misiontic.2020.grupod@gmail.com', 'Karen.1234')

            serverEmail.send(to=email, subject='Recuperar contraseña',
                             contents='Hola! haz olvidado tu contraseña..... Esta es tu contraseña:')

            flash('Revisa en tu correo la contraseña')

            return render_template('login.html')
        return render_template('forgot.html')
    except Exception as e:
        print("Ocurrio un eror:", e)
        return render_template('forgot.html')


@app.route('/mensaje')
@login_required  # DAVID
def Message():
    return jsonify({'usuario': mensajes, 'mensaje': "Estos son los mensajes"})


if __name__ == '__main__':
   # app.run(host='0.0.0.0', port =443, ssl_context=('micertificado.pem', 'llaveprivada.pem'))
     app.run(host='127.0.0.1', port=443, ssl_context=('micertificado.pem', 'llaveprivada.pem'))
