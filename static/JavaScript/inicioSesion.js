function validacion() {
    var usuario = document.formulario.usuario;
    var pass = document.formulario.password;

    var longitud_usuario = usuario.value.length;
    if (longitud_usuario < 5) {
        alert("Debe ingresar en el nombre de usuario minimo 5 caracteres");
    }

    var longitud_pass = pass.value.length;
    if (longitud_pass < 8) {
        alert("Debe ingresar una contraseña con minimo 8 caracteres");
    }

};

function mostrarPassword() {
    var mostrar = document.getElementById('password');
    mostrar.type = "text";
    //mostrar.style.width = "80%";

}

function ocultarPassword() {
    var ocultar = document.getElementById('password');
    ocultar.type = "password";
    //ocultar.style.width = "100%";
}

function DameLaFechaHora() {
      var hora = new Date()
      var hrs = hora.getHours();
      var min = hora.getMinutes();
      var hoy = new Date();
      var m = new Array();
      var d = new Array()
      var an= hoy.getYear();
      m[0]="Enero";  m[1]="Febrero";  m[2]="Marzo";
      m[3]="Abril";   m[4]="Mayo";  m[5]="Junio";
      m[6]="Julio";    m[7]="Agosto";   m[8]="Septiembre";
      m[9]="Octubre";   m[10]="Noviembre"; m[11]="Diciembre";
      document.write(hoy.getDate());
      document.write(" de ");
      document.write(m[hoy.getMonth()]);
      document.write( " " );
      document.write("hora: "+hrs+":"+min);
}

function selectProduct(imgId) {
    var seleccion = document.getElementById(imgId);
    seleccion.style.width = "150px";
    seleccion.style.height = "150px";
}
function deselectProduct(imgId) {
    var seleccion = document.getElementById(imgId);
    seleccion.style.width = "140px";
    seleccion.style.height = "140px";
}