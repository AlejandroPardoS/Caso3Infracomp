package src2.servidor;

public class Servicio {
    private int id;
    private String nombre;
    private String ip;
    private int puerto;

    // Constructor, getters, setters
    public Servicio(int id, String nombre, String ip, int puerto) {
        this.id = id;
        this.nombre = nombre;
        this.ip = ip;
        this.puerto = puerto;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getPuerto() {
        return puerto;
    }

    public void setPuerto(int puerto) {
        this.puerto = puerto;
    }

    @Override
    public String toString() {
        return String.format("{\"id\":%d,\"nombre\":\"%s\",\"ip\":\"%s\",\"puerto\":%d}",
                             id, nombre, ip, puerto);
    }
    
}