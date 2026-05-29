<?php
require_once "includes/inc_all.php";

enforceUserPermission('module_support');

$client_id_filter = isset($_GET['client_id']) ? intval($_GET['client_id']) : 0;
$client_filter_clause = '';
$client_name = '';
if ($client_id_filter > 0) {
    enforceClientAccess();
    $client_filter_clause = "AND a.asset_client_id = $client_id_filter";
    $row_c = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT client_name FROM clients WHERE client_id = $client_id_filter"));
    $client_name = nullable_htmlentities($row_c['client_name'] ?? '');
}

// Graph nodes = assets that either have at least one port (device) OR are
// connected via a port (host). Edges = port_to_port_id (cable chains)
// + port → connected asset attachments.
$nodes = [];
$edges = [];
$node_seen = [];

// 1. Devices: any asset with rows in asset_ports.
$dev_q = mysqli_query($mysqli, "
    SELECT DISTINCT a.asset_id, a.asset_name, a.asset_type, a.asset_make, a.asset_model,
           c.client_name, l.location_name
    FROM assets a
    LEFT JOIN clients   c ON c.client_id   = a.asset_client_id
    LEFT JOIN locations l ON l.location_id = a.asset_location_id
    WHERE EXISTS (SELECT 1 FROM asset_ports WHERE port_device_asset_id = a.asset_id AND port_archived_at IS NULL)
      AND a.asset_archived_at IS NULL
      $client_filter_clause
    ORDER BY a.asset_name
");
while ($d = mysqli_fetch_assoc($dev_q)) {
    $aid = intval($d['asset_id']);
    $nid = 'asset_' . $aid;
    $node_seen[$nid] = true;
    $nodes[] = [
        'data' => [
            'id'         => $nid,
            'label'      => $d['asset_name'],
            'asset_type' => $d['asset_type'],
            'asset_make' => $d['asset_make']  ?? '',
            'asset_model'=> $d['asset_model'] ?? '',
            'client'     => $d['client_name'],
            'location'   => $d['location_name'] ?? '',
            'category'   => 'device',
            'href'       => 'network_device_details.php?id=' . $aid,
        ],
    ];
}

// 2. Patch chains: port_to_port_id pairs (undirected, emit once).
$chains_clause = $client_id_filter > 0 ? "AND a_a.asset_client_id = $client_id_filter" : '';
$chains_q = mysqli_query($mysqli, "
    SELECT pa.port_id AS pa_id, pa.port_number AS pa_num,
           pb.port_id AS pb_id, pb.port_number AS pb_num,
           a_a.asset_id AS dev_a, a_b.asset_id AS dev_b,
           av.vlan_color AS access_v_color, av.vlan_number AS access_v_num
    FROM asset_ports pa
    JOIN asset_ports pb ON pa.port_to_port_id = pb.port_id AND pa.port_id < pb.port_id
    JOIN assets a_a ON a_a.asset_id = pa.port_device_asset_id
    JOIN assets a_b ON a_b.asset_id = pb.port_device_asset_id
    LEFT JOIN vlans av ON av.vlan_id = pa.port_access_vlan_id
    WHERE pa.port_archived_at IS NULL AND pb.port_archived_at IS NULL
      AND a_a.asset_archived_at IS NULL AND a_b.asset_archived_at IS NULL
      $chains_clause
");
while ($e = mysqli_fetch_assoc($chains_q)) {
    $edges[] = [
        'data' => [
            'id'         => 'patch_' . intval($e['pa_id']) . '_' . intval($e['pb_id']),
            'source'     => 'asset_' . intval($e['dev_a']),
            'target'     => 'asset_' . intval($e['dev_b']),
            'sourceLabel'=> '#' . intval($e['pa_num']),
            'targetLabel'=> '#' . intval($e['pb_num']),
            'kind'       => 'patch',
            'vlanColor'  => $e['access_v_color'] ?? '',
            'vlanNumber' => $e['access_v_num']   ? intval($e['access_v_num']) : 0,
        ],
    ];
}

// 3. Asset attachments: port → connected_asset.
$att_clause = $client_id_filter > 0 ? "AND da.asset_client_id = $client_id_filter" : '';
$att_q = mysqli_query($mysqli, "
    SELECT DISTINCT ca.asset_id AS conn_id, ca.asset_name AS conn_name, ca.asset_type AS conn_type,
           ca.asset_make AS conn_make, ca.asset_model AS conn_model,
           da.asset_id AS dev_id,
           p.port_id, p.port_number,
           av.vlan_color AS access_v_color, av.vlan_number AS access_v_num
    FROM asset_ports p
    JOIN assets da ON da.asset_id = p.port_device_asset_id
    JOIN assets ca ON ca.asset_id = p.port_connected_asset_id
    LEFT JOIN vlans av ON av.vlan_id = p.port_access_vlan_id
    WHERE p.port_archived_at IS NULL
      AND da.asset_archived_at IS NULL
      AND ca.asset_archived_at IS NULL
      $att_clause
");
while ($a = mysqli_fetch_assoc($att_q)) {
    $aid = intval($a['conn_id']);
    $nid = 'asset_' . $aid;
    if (!isset($node_seen[$nid])) {
        $nodes[] = [
            'data' => [
                'id'          => $nid,
                'label'       => $a['conn_name'],
                'asset_type'  => $a['conn_type'],
                'asset_make'  => $a['conn_make']  ?? '',
                'asset_model' => $a['conn_model'] ?? '',
                'category'    => 'host',
                'href'        => 'assets.php?client_id=' . $client_id_filter,
            ],
        ];
        $node_seen[$nid] = true;
    }
    $edges[] = [
        'data' => [
            'id'          => 'attach_' . intval($a['port_id']),
            'source'      => 'asset_' . intval($a['dev_id']),
            'target'      => $nid,
            'sourceLabel' => '#' . intval($a['port_number']),
            'targetLabel' => '',
            'kind'        => 'attach',
            'vlanColor'   => $a['access_v_color'] ?? '',
            'vlanNumber'  => $a['access_v_num']   ? intval($a['access_v_num']) : 0,
        ],
    ];
}

// VLAN palette for the filter UI.
$vlans_clause = $client_id_filter > 0 ? "WHERE vlan_client_id = $client_id_filter AND vlan_archived_at IS NULL" : "WHERE vlan_archived_at IS NULL";
$vlans = [];
$vlans_q = mysqli_query($mysqli, "SELECT vlan_id, vlan_number, vlan_name, vlan_color FROM vlans $vlans_clause ORDER BY vlan_number");
while ($v = mysqli_fetch_assoc($vlans_q)) {
    $vlans[] = $v;
}

$graph_json = json_encode(['nodes' => $nodes, 'edges' => $edges], JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

// Pull FontAwesome 5 Solid SVG path data for the icons we use in the
// topology nodes. Done server-side so the browser doesn't have to
// fetch each icon separately; cytoscape uses data-URI backgrounds
// which can't reference webfonts reliably.
$icon_names = ['network-wired','fire-alt','wifi','server','cloud','ethernet','plug','th','laptop','desktop','print','video','mobile-alt','tablet-alt','tv','tag'];
$icon_paths = [];
$svg_dir = $_SERVER['DOCUMENT_ROOT'] . '/plugins/fontawesome-free/svgs/solid';
foreach ($icon_names as $name) {
    $f = $svg_dir . '/' . $name . '.svg';
    if (!is_file($f)) continue;
    $svg = file_get_contents($f);
    // Extract viewBox + first path's d attribute.
    if (preg_match('/viewBox=["\']([^"\']+)["\']/', $svg, $vm) &&
        preg_match('/<path[^>]*\sd=["\']([^"\']+)["\']/i', $svg, $pm)) {
        $icon_paths[$name] = ['vb' => $vm[1], 'd' => $pm[1]];
    }
}
$icon_paths_json = json_encode($icon_paths, JSON_UNESCAPED_SLASHES);
?>

<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2">
            <i class="fas fa-fw fa-project-diagram mr-2"></i>Network topology
            <?php if ($client_name) { ?>
                — <small><?= $client_name ?></small>
            <?php } ?>
        </h3>
        <div class="card-tools">
            <a href="network_devices.php<?= $client_id_filter ? '?client_id=' . $client_id_filter : '' ?>" class="btn btn-outline-light">
                <i class="fa fa-fw fa-list mr-1"></i>Device list
            </a>
        </div>
    </div>
    <div class="card-body">

        <?php if (empty($nodes)) { ?>
            <div class="alert alert-info">
                <i class="fa fa-fw fa-info-circle mr-1"></i>
                Nothing to graph yet. Add ports to a switch / patch panel asset via
                <a href="network_devices.php<?= $client_id_filter ? '?client_id=' . $client_id_filter : '' ?>">Switches &amp; patches</a>,
                then connect ports to other assets or chain them to other ports.
            </div>
        <?php } else { ?>

            <div class="row mb-3">
                <div class="col-md-3">
                    <label class="small text-muted mb-1">Layout</label>
                    <select id="topoLayout" class="form-control form-control-sm">
                        <option value="dagre">Hierarchical (UniFi-style)</option>
                        <option value="cose">Force-directed</option>
                        <option value="concentric">Concentric</option>
                        <option value="circle">Circle</option>
                        <option value="grid">Grid</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="small text-muted mb-1">Search</label>
                    <input type="search" id="topoSearch" class="form-control form-control-sm" placeholder="Find device or asset">
                </div>
                <div class="col-md-3">
                    <label class="small text-muted mb-1">Filter by VLAN</label>
                    <select id="topoVlanFilter" class="form-control form-control-sm">
                        <option value="">- All VLANs -</option>
                        <?php foreach ($vlans as $v) { ?>
                            <option value="<?= intval($v['vlan_number']) ?>" data-color="<?= htmlentities($v['vlan_color']) ?>">
                                VLAN <?= intval($v['vlan_number']) ?> — <?= nullable_htmlentities($v['vlan_name']) ?>
                            </option>
                        <?php } ?>
                    </select>
                </div>
                <div class="col-md-3 d-flex align-items-end">
                    <button id="topoFitBtn" class="btn btn-sm btn-secondary mr-2"><i class="fa fa-fw fa-expand"></i> Fit</button>
                    <button id="topoResetBtn" class="btn btn-sm btn-secondary"><i class="fa fa-fw fa-undo"></i> Reset</button>
                </div>
            </div>

            <div id="topoLegend" class="small text-secondary mb-2">
                <strong>Tip:</strong> click a node to highlight its connections. Shift-click two nodes to trace the cable path between them. Double-click a device to open its faceplate. Drag nodes to position them.
            </div>

            <div id="topoStatus" class="small text-muted mb-2"></div>

            <div id="cy" style="width:100%;height:78vh;border:1px solid #e1e4e8;background:#ffffff;border-radius:6px;"></div>

            <!--
                The SVG node icons reference 'Font Awesome 5 Free' Solid. The
                style sheet already loads via inc_all.php, but SVG <text>
                rendering inside cytoscape's data-URI background needs the
                font to be loaded into the document first. The injected link
                below is a no-op when AdminLTE's bundle already pulled it.
            -->
            <link rel="stylesheet" href="/plugins/fontawesome-free/css/all.min.css">

        <?php } ?>
    </div>
</div>

<?php if (!empty($nodes)) { ?>
<script src="/plugins/cytoscape/cytoscape.min.js"></script>
<script src="/plugins/cytoscape/dagre.min.js"></script>
<script src="/plugins/cytoscape/cytoscape-dagre.min.js"></script>

<script>
(function(){
    if (typeof cytoscape === 'undefined') {
        document.getElementById('topoStatus').innerHTML =
            "<span class='text-danger'>Could not load cytoscape.js from /plugins/cytoscape/.</span>";
        return;
    }
    if (typeof cytoscapeDagre !== 'undefined') {
        cytoscape.use(cytoscapeDagre);
    }

    var graph = <?= $graph_json ?>;

    // ---------- UniFi-style icon + colour palette per asset type ----------
    // The icon path data was pulled from FontAwesome 5 Free Solid server-side
    // and inlined here. Each entry: { vb: viewBox string, d: SVG path }.
    var iconPaths = <?= $icon_paths_json ?>;

    var assetTypeIcon = function(t) {
        t = (t || '').toLowerCase();
        // Match the PHP getAssetIcon() exactly — same FA slugs.
        if (t.indexOf('switch') !== -1)        return {icon: 'network-wired', bg: '#0559c9'}; // network-wired
        if (t.indexOf('patch') !== -1)         return {icon: 'ethernet', bg: '#5a6c7d'}; // ethernet
        if (t.indexOf('keystone') !== -1)      return {icon: 'plug', bg: '#1abc9c'}; // plug
        if (t.indexOf('wallbox') !== -1)       return {icon: 'th', bg: '#95a5a6'}; // th
        if (t.indexOf('firewall') !== -1 ||
            t.indexOf('router') !== -1)        return {icon: 'fire-alt', bg: '#c0392b'}; // fire-alt
        if (t.indexOf('access point') !== -1)  return {icon: 'wifi', bg: '#8e44ad'}; // wifi
        if (t.indexOf('server') !== -1)        return {icon: 'server', bg: '#d35400'}; // server
        if (t.indexOf('vm') !== -1 ||
            t.indexOf('virtual') !== -1)       return {icon: 'cloud', bg: '#16a085'}; // cloud
        if (t.indexOf('printer') !== -1)       return {icon: 'print', bg: '#34495e'}; // print
        if (t.indexOf('camera') !== -1)        return {icon: 'video', bg: '#7f8c8d'}; // video
        if (t.indexOf('laptop') !== -1)        return {icon: 'laptop', bg: '#27ae60'}; // laptop
        if (t.indexOf('desktop') !== -1)       return {icon: 'desktop', bg: '#27ae60'};
        if (t.indexOf('phone') !== -1)         return {icon: 'mobile-alt', bg: '#2c3e50'}; // mobile-alt
        if (t.indexOf('tablet') !== -1)        return {icon: 'tablet-alt', bg: '#2c3e50'};
        return {icon: 'tag', bg: '#7f8c8d'};
    };

    // Build the per-node SVG: a UniFi-style white "card" with a soft
    // shadow, the device icon coloured by asset-type in the upper area,
    // and a small model-name chip in the lower area. The chip is baked
    // into the SVG so cytoscape's `label` can stay clean (= asset name).
    //
    // Coordinate system: 140 wide × 100 tall.
    //   - Card:  x4-y4 to x136-y96, rounded 12px
    //   - Icon:  centred on (70, 38), 38px tall
    //   - Chip:  rounded pill centred on y=78, height 16px
    function escXml(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    function nodeIconDataUri(spec, modelText) {
        var iconBlock = '';
        var entry = iconPaths[spec.icon] || iconPaths['tag'];
        if (entry) {
            var vbParts = entry.vb.split(/\s+/).map(parseFloat);
            var vbW = vbParts[2] || 512, vbH = vbParts[3] || 512;
            var maxDim = Math.max(vbW, vbH);
            var scale = 38 / maxDim;
            var iconW = vbW * scale, iconH = vbH * scale;
            var tx = 70 - iconW / 2;
            var ty = 38 - iconH / 2;
            iconBlock =
                "<g transform='translate(" + tx.toFixed(2) + " " + ty.toFixed(2) + ") scale(" + scale.toFixed(4) + ")'>" +
                  "<path d='" + entry.d + "' fill='" + spec.bg + "'/>" +
                "</g>";
        }
        var chipBlock = '';
        var trimmed = (modelText || '').trim();
        if (trimmed !== '') {
            if (trimmed.length > 22) trimmed = trimmed.slice(0, 22) + '…';
            // Approximate text width: 6.2px per char at 10px font, +14px padding.
            var chipW = Math.min(120, trimmed.length * 6.2 + 14);
            var chipX = (140 - chipW) / 2;
            chipBlock =
                "<rect x='" + chipX.toFixed(1) + "' y='70' width='" + chipW.toFixed(1) + "' height='16' rx='8' " +
                      "fill='#f0f2f5' stroke='#e1e4e8' stroke-width='1'/>" +
                "<text x='70' y='81.5' text-anchor='middle' font-family='Helvetica,Arial,sans-serif' " +
                      "font-size='10' fill='#6c7a89'>" + escXml(trimmed) + "</text>";
        }
        var svg =
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 140 100'>" +
              "<defs><filter id='s' x='-10%' y='-10%' width='120%' height='120%'>" +
                "<feDropShadow dx='0' dy='2' stdDeviation='3' flood-opacity='0.10'/>" +
              "</filter></defs>" +
              "<rect x='4' y='4' width='132' height='92' rx='12' ry='12' " +
                    "fill='#ffffff' stroke='#e1e4e8' stroke-width='1' filter='url(#s)'/>" +
              iconBlock +
              chipBlock +
            "</svg>";
        return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
    }

    graph.nodes.forEach(function(n){
        var spec = assetTypeIcon(n.data.asset_type);
        var modelText = [n.data.asset_make, n.data.asset_model].filter(Boolean).join(' ');
        n.data.icon = nodeIconDataUri(spec, modelText);
        n.data.bg   = spec.bg;
    });

    // UniFi accent green — used for default edges + selection highlights.
    var ACCENT = '#00b87a';

    var cy = cytoscape({
        container: document.getElementById('cy'),
        elements: graph,
        style: [
            // ---------- Nodes (white card with colored icon + model chip) ----------
            // The card body, shadow and rounded corners are *baked into* the
            // SVG itself (viewBox 0 0 140 100). The cytoscape node is therefore
            // a plain rectangle of the same dimensions with the SVG as its
            // background, fitted exactly — no shape-clipping, no double-rounding.
            {
                selector: 'node',
                style: {
                    'background-color': '#ffffff',
                    'background-image': 'data(icon)',
                    'background-fit': 'contain',
                    'background-image-containment': 'inside',
                    'background-clip': 'none',
                    'background-opacity': 0,
                    'background-width': '100%',
                    'background-height': '100%',
                    'shape': 'rectangle',
                    'label': 'data(label)',
                    'color': '#1f2d3d',
                    'font-size': '12px',
                    'font-weight': 600,
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 8,
                    'text-wrap': 'wrap',
                    'text-max-width': '180px',
                    'width': 140, 'height': 100,
                    'border-width': 0,
                    'overlay-opacity': 0
                }
            },

            // ---------- Edges (smooth bezier, teal) ----------
            {
                selector: 'edge',
                style: {
                    'curve-style': 'unbundled-bezier',
                    'control-point-distances': [40],
                    'control-point-weights': [0.5],
                    'width': 1.5,
                    'line-color': ACCENT,
                    'target-arrow-shape': 'none',

                    // UniFi-style port-number labels at both endpoints.
                    'source-label': 'data(sourceLabel)',
                    'target-label': 'data(targetLabel)',
                    'source-text-offset': 22,
                    'target-text-offset': 22,
                    'edge-text-rotation': 'autorotate',
                    'font-size': '10px',
                    'font-weight': 500,
                    'color': ACCENT,
                    'text-background-opacity': 1,
                    'text-background-color': '#ffffff',
                    'text-background-padding': '2px',
                    'text-margin-y': -8
                }
            },
            // Solid for cable chains, subtly dashed for "just attached" hosts.
            { selector: 'edge[kind = "attach"]', style: { 'line-style': 'solid' } },
            { selector: 'edge[kind = "patch"]',  style: { 'line-style': 'solid', 'width': 2 } },

            // ---------- Highlight / faded / path-trace ----------
            { selector: '.faded',           style: { 'opacity': 0.22 } },
            { selector: 'node.highlighted', style: { 'border-width': 0, 'underlay-color': ACCENT, 'underlay-padding': 6, 'underlay-opacity': 0.20 } },
            { selector: 'edge.highlighted', style: { 'line-color': '#f39c12', 'color': '#f39c12', 'width': 3 } },
            { selector: '.path-trace',      style: { 'line-color': ACCENT, 'color': ACCENT, 'width': 4 } },
            { selector: 'node.path-trace',  style: { 'underlay-color': ACCENT, 'underlay-padding': 8, 'underlay-opacity': 0.25 } }
        ],
        // UniFi's topology is a left-to-right tree with the WAN / root on
        // the left, switches branching right, hosts as leaves.
        layout: {
            name: 'dagre',
            rankDir: 'LR',
            nodeSep: 36,
            edgeSep: 18,
            rankSep: 140,
            animate: true,
            padding: 40
        },
        wheelSensitivity: 0.2,
        minZoom: 0.2,
        maxZoom: 2.5
    });

    function updateStatus() {
        document.getElementById('topoStatus').textContent =
            cy.nodes().length + ' nodes · ' + cy.edges().length + ' edges';
    }
    updateStatus();

    document.getElementById('topoLayout').addEventListener('change', function(){
        var name = this.value;
        var opts = { name: name, animate: true, padding: 40 };
        if (name === 'cose') opts.randomize = true;
        if (name === 'dagre') {
            // LR tree by default — matches UniFi's reading order.
            opts.rankDir = 'LR';
            opts.nodeSep = 36;
            opts.edgeSep = 18;
            opts.rankSep = 140;
        }
        cy.layout(opts).run();
    });

    document.getElementById('topoFitBtn').addEventListener('click', function(){ cy.fit(); });
    document.getElementById('topoResetBtn').addEventListener('click', function(){
        cy.elements().removeClass('faded highlighted path-trace');
        pathStart = null;
        cy.fit();
    });

    document.getElementById('topoSearch').addEventListener('input', function(){
        var q = this.value.trim().toLowerCase();
        if (!q) { cy.elements().removeClass('faded highlighted'); return; }
        var hits = cy.nodes().filter(function(n){ return (n.data('label') || '').toLowerCase().indexOf(q) !== -1; });
        cy.elements().addClass('faded');
        hits.removeClass('faded').addClass('highlighted');
        hits.connectedEdges().removeClass('faded');
        hits.neighborhood().removeClass('faded');
        if (hits.length === 1) cy.center(hits[0]);
    });

    document.getElementById('topoVlanFilter').addEventListener('change', function(){
        var v = parseInt(this.value, 10);
        cy.elements().removeClass('faded');
        if (!v) return;
        var matchingEdges = cy.edges().filter(function(e){ return parseInt(e.data('vlanNumber'),10) === v; });
        cy.elements().addClass('faded');
        matchingEdges.removeClass('faded');
        matchingEdges.connectedNodes().removeClass('faded');
    });

    cy.on('tap', 'node', function(evt){
        if (evt.originalEvent && evt.originalEvent.shiftKey) { handlePathClick(evt.target); return; }
        cy.elements().removeClass('faded highlighted path-trace');
        var n = evt.target;
        var nb = n.neighborhood().add(n);
        cy.elements().not(nb).addClass('faded');
        n.addClass('highlighted');
    });
    cy.on('tap', function(evt){
        if (evt.target === cy) {
            cy.elements().removeClass('faded highlighted path-trace');
            pathStart = null;
        }
    });

    var pathStart = null;
    function handlePathClick(node) {
        if (!pathStart) {
            pathStart = node;
            cy.elements().removeClass('faded highlighted path-trace');
            node.addClass('highlighted');
            document.getElementById('topoStatus').textContent =
                'Start: ' + node.data('label') + ' — shift-click another node to trace the path.';
            return;
        }
        if (pathStart.id() === node.id()) { pathStart = null; cy.elements().removeClass('faded highlighted path-trace'); updateStatus(); return; }
        var dij = cy.elements().aStar({ root: pathStart, goal: node, directed: false });
        cy.elements().addClass('faded');
        if (dij.found) {
            dij.path.removeClass('faded').addClass('path-trace');
            document.getElementById('topoStatus').textContent =
                'Path: ' + pathStart.data('label') + ' → ' + node.data('label') + ' (' + (dij.path.length-1) + ' hops)';
        } else {
            document.getElementById('topoStatus').innerHTML =
                "<span class='text-danger'>No path between " + pathStart.data('label') + " and " + node.data('label') + "</span>";
        }
        pathStart = null;
    }

    cy.on('dbltap', 'node', function(evt){
        var href = evt.target.data('href');
        if (href) window.location = href;
    });
})();
</script>
<?php } ?>

<?php require_once "../includes/footer.php"; ?>
