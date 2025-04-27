package src2.servidor;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ServicioManager {

    private final Map<Integer, Servicio> servicios;
    private final Map<Integer, String> nombresServicios;

    public ServicioManager() {
        servicios = new HashMap<>();

        // Ejemplo de servicios predefinidos
        servicios.put(1, new Servicio(1, "EstadoVuelo", "127.0.0.1", 3001));
        servicios.put(2, new Servicio(2, "Disponibilidad", "127.0.0.1", 3002));
        servicios.put(3, new Servicio(3, "CostoVuelo", "127.0.0.1", 3003));

        nombresServicios = new HashMap<>();
        nombresServicios.put(1, "EstadoVuelo");
        nombresServicios.put(2, "Disponibilidad");
        nombresServicios.put(3, "CostoVuelo");
    }
        

    public Servicio obtenerServicio(int id) {
        return servicios.get(id);
    }

    public boolean existeServicio(int id) {
        return servicios.containsKey(id);
    }

    public Collection<Servicio> obtenerTodos() {
        return servicios.values();
    }

    public String obtenerNombreServicio(int id) {
        return nombresServicios.get(id);
    }

    public Map<Integer, String> obtenerNombresServicios() {
        return nombresServicios;
    }
    
}
