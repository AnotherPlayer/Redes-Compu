import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.List;

public class CalculatorUI extends JFrame {

    // Paleta de colores "Deep Ocean"
    private final Color COLOR_FONDO = new Color(13, 17, 23);      // Azul casi negro
    private final Color COLOR_PANEL = new Color(22, 27, 34);      // Gris azulado oscuro
    private final Color COLOR_ACCENTO = new Color(31, 111, 235);  // Azul vibrante
    private final Color COLOR_TEXTO = new Color(201, 209, 217);   // Gris claro/blanco
    private final Color COLOR_BORDE = new Color(48, 54, 61);      // Gris para bordes

    private final JTextField ipField = createStyledTextField("190.0.0.0");
    private final JTextField hostField = createStyledTextField("100");

    private final JLabel classValue = createValueLabel("-");
    private final JLabel defaultMaskValue = createValueLabel("-");
    private final JLabel subnetCountValue = createValueLabel("-");
    private final JLabel hostPerSubnetValue = createValueLabel("-");
    private final JLabel newMaskValue = createValueLabel("-");
    private final JLabel prefixValue = createValueLabel("-");

    private final DefaultListModel<String> subnetListModel = new DefaultListModel<>();
    private final DefaultListModel<String> hostListModel = new DefaultListModel<>();
    private final JList<String> subnetList = new JList<>(subnetListModel);
    private final JList<String> hostList = new JList<>(hostListModel);

    private int currentPrefix = -1;
    private String currentIp = "";

    public CalculatorUI() {
        setTitle("Calculadora de Subredes IPv4");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(1100, 750);
        setLocationRelativeTo(null);

        JPanel content = new JPanel(new BorderLayout(20, 20));
        content.setBorder(new EmptyBorder(25, 25, 25, 25));
        content.setBackground(COLOR_FONDO);
        setContentPane(content);

        content.add(buildTopSection(), BorderLayout.NORTH);
        content.add(buildListSection(), BorderLayout.CENTER);
    }

    private JPanel buildTopSection() {
        JPanel container = new JPanel(new BorderLayout(20, 20));
        container.setOpaque(false);

        // Grid para inputs y resumen
        JPanel grid = new JPanel(new GridLayout(1, 2, 20, 0));
        grid.setOpaque(false);

        // Panel Izquierdo: Entradas
        JPanel inputs = new JPanel();
        inputs.setLayout(new BoxLayout(inputs, BoxLayout.Y_AXIS));
        inputs.setOpaque(false);
        inputs.add(buildInputRow("Dirección IP", ipField));
        inputs.add(Box.createVerticalStrut(15));
        inputs.add(buildInputRow("Host requeridos", hostField));

        // Panel Derecho: Resumen
        RoundedPanel summary = new RoundedPanel(20, COLOR_PANEL);
        summary.setLayout(new GridLayout(3, 2, 10, 10));
        summary.setBorder(new EmptyBorder(15, 20, 15, 20));
        
        summary.add(createSummaryItem("Clase:", classValue));
        summary.add(createSummaryItem("M. Red:", defaultMaskValue));
        summary.add(createSummaryItem("Subredes:", subnetCountValue));
        summary.add(createSummaryItem("Hosts/Subred:", hostPerSubnetValue));
        summary.add(createSummaryItem("Nueva Máscara:", newMaskValue));
        summary.add(createSummaryItem("Prefijo:", prefixValue));

        grid.add(inputs);
        grid.add(summary);

        // Botón Calcular
        JButton calculateBtn = new JButton("Calcular Subredes");
        calculateBtn.setBackground(COLOR_ACCENTO);
        calculateBtn.setForeground(Color.WHITE);
        calculateBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        calculateBtn.setFocusPainted(false);
        calculateBtn.setBorder(new EmptyBorder(10, 30, 10, 30));
        calculateBtn.addActionListener(this::runCalculation);

        JPanel btnWrapper = new JPanel(new FlowLayout(FlowLayout.CENTER));
        btnWrapper.setOpaque(false);
        btnWrapper.add(calculateBtn);

        container.add(grid, BorderLayout.CENTER);
        container.add(btnWrapper, BorderLayout.SOUTH);

        return container;
    }

    private JPanel buildInputRow(String labelText, JTextField field) {
        JPanel row = new JPanel(new BorderLayout(15, 0));
        row.setOpaque(false);

        RoundedPanel labelBg = new RoundedPanel(15, COLOR_ACCENTO);
        labelBg.setPreferredSize(new Dimension(140, 40));
        labelBg.setLayout(new BorderLayout());
        JLabel label = new JLabel(labelText, SwingConstants.CENTER);
        label.setForeground(Color.WHITE);
        label.setFont(new Font("SansSerif", Font.BOLD, 13));
        labelBg.add(label);

        row.add(labelBg, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        return row;
    }

    private JPanel createSummaryItem(String title, JLabel value) {
        JPanel item = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        item.setOpaque(false);
        JLabel t = new JLabel(title);
        t.setForeground(COLOR_ACCENTO);
        t.setFont(new Font("SansSerif", Font.BOLD, 12));
        value.setForeground(COLOR_TEXTO);
        item.add(t);
        item.add(value);
        return item;
    }

    private JPanel buildListSection() {
        JPanel lists = new JPanel(new GridLayout(1, 2, 20, 0));
        lists.setOpaque(false);

        lists.add(createListBlock("Subredes Calculadas", subnetList));
        lists.add(createListBlock("Hosts de la Subred", hostList));

        subnetList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateHostList();
        });

        return lists;
    }

    private JPanel createListBlock(String title, JList<String> list) {
        JPanel block = new JPanel(new BorderLayout(0, 10));
        block.setOpaque(false);

        RoundedPanel headerBg = new RoundedPanel(15, COLOR_BORDE);
        headerBg.setPreferredSize(new Dimension(0, 35));
        headerBg.setLayout(new BorderLayout());
        JLabel header = new JLabel(title, SwingConstants.CENTER);
        header.setForeground(COLOR_TEXTO);
        header.setFont(new Font("SansSerif", Font.BOLD, 13));
        headerBg.add(header);

        list.setBackground(COLOR_PANEL);
        list.setForeground(COLOR_TEXTO);
        list.setSelectionBackground(COLOR_ACCENTO);
        list.setFont(new Font("Monospaced", Font.PLAIN, 13));

        JScrollPane scroll = new JScrollPane(list);
        scroll.setBorder(BorderFactory.createLineBorder(COLOR_BORDE));
        scroll.getViewport().setBackground(COLOR_PANEL);

        block.add(headerBg, BorderLayout.NORTH);
        block.add(scroll, BorderLayout.CENTER);
        return block;
    }

    private JTextField createStyledTextField(String text) {
        JTextField f = new JTextField(text);
        f.setBackground(COLOR_PANEL);
        f.setForeground(Color.WHITE);
        f.setCaretColor(Color.WHITE);
        f.setFont(new Font("SansSerif", Font.PLAIN, 15));
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDE, 1),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        return f;
    }

    private JLabel createValueLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("SansSerif", Font.PLAIN, 13));
        return l;
    }

    // --- LÓGICA DE CÁLCULO (Mantenida del original) ---
    private void runCalculation(ActionEvent event) {
        String ip = ipField.getText().trim();
        int desiredHosts;
        try {
            desiredHosts = Integer.parseInt(hostField.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Número de hosts inválido.");
            return;
        }

        int defaultPrefix = IpCalculatorOperations.getDefaultPrefix(ip);
        if (defaultPrefix < 0) {
            JOptionPane.showMessageDialog(this, "IP no válida.");
            return;
        }

        int prefix = IpCalculatorOperations.calculatePrefixForHosts(desiredHosts);
        if (prefix < 0 || prefix < defaultPrefix) {
            JOptionPane.showMessageDialog(this, "Configuración no compatible.");
            return;
        }

        currentIp = ip;
        currentPrefix = prefix;

        classValue.setText(IpCalculatorOperations.getIpClass(ip));
        defaultMaskValue.setText(IpCalculatorOperations.getDefaultMask(ip));
        subnetCountValue.setText(String.valueOf(IpCalculatorOperations.calculateSubnetCount(ip, prefix)));
        hostPerSubnetValue.setText(String.valueOf(IpCalculatorOperations.calculateHostsPerSubnet(prefix)));
        newMaskValue.setText(IpCalculatorOperations.getMaskFromPrefix(prefix));
        prefixValue.setText("/" + prefix);

        loadSubnets();
    }

    private void loadSubnets() {
        subnetListModel.clear();
        List<String> subnets = IpCalculatorOperations.listSubnets(currentIp, currentPrefix, 512);
        for (String s : subnets) subnetListModel.addElement(s);
        if (!subnetListModel.isEmpty()) subnetList.setSelectedIndex(0);
    }

    private void updateHostList() {
        hostListModel.clear();
        int idx = subnetList.getSelectedIndex();
        if (idx < 0 || currentPrefix < 0) return;
        List<String> hosts = IpCalculatorOperations.listHostsForSubnet(currentIp, currentPrefix, idx, 256);
        for (String h : hosts) hostListModel.addElement(h);
    }

    // Clase interna para paneles redondeados
    class RoundedPanel extends JPanel {
        private int radius;
        public RoundedPanel(int radius, Color bg) {
            this.radius = radius;
            setBackground(bg);
            setOpaque(false);
        }
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fill(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), radius, radius));
            g2.dispose();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new CalculatorUI().setVisible(true));
    }
}