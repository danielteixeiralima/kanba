$(document).ready(function(){
    $('.dropdown').hover(function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeIn(500);
    }, function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeOut(500);
    });

    // Adiciona um listener de evento 'change' para o elemento de seleção da empresa
    $('#empresa').change(function() {
        updateObjectives();
    });

    // Adiciona um listener de evento 'change' para o elemento de seleção do objetivo
    $('#objetivo').change(function() {
        var objetivoId = $(this).val();
        $('#id_okr').val(objetivoId);
    });

    // Chama a função updateObjectives quando a página é carregada
    updateObjectives();

    // Adicione event listeners nos botões de aprovar e recusar
    $('.btn-approve').click(function(e) {
        if (!confirm('Tem certeza de que deseja aprovar esta macro ação? Ela será inserida no banco de dados.')) {
            e.preventDefault();  // Cancela a ação do clique se o usuário clicar em "Cancelar"
        }
    });

    $('.btn-reject').click(function(e) {
        if (!confirm('Tem certeza de que deseja recusar esta macro ação? Ela será excluída.')) {
            e.preventDefault();  // Cancela a ação do clique se o usuário clicar em "Cancelar"
        }
    });
});



function updateObjectives() {
var objetivoOriginal = $('#objetivo').data('original');
    var empresaId = $('#empresa').val();


    $.getJSON('/get_okrs/' + empresaId, function(data) {
        var select = $('#objetivo');
        select.empty();
        data.forEach(function(okr) {
            var option = $('<option>');
            option.val(okr.id);  // Define o valor da opção para o ID do objetivo
            option.text(okr.objetivo);
            if (okr.id == objetivoOriginal) {
                option.prop('selected', true);
            }
            select.append(option);
        });
        // Atualize o campo oculto 'id_okr' para refletir o primeiro objetivo na lista, a menos que um objetivo original esteja definido
        if (objetivoOriginal) {
            $('#id_okr').val(objetivoOriginal);
        } else {
            $('#id_okr').val($('#objetivo').val());
        }
    });
    $.getJSON('/get_empresa_info/' + empresaId, function(data) {
        var select = $('#objetivo');
        select.empty();
        data.objetivos.forEach(function(objetivo) {
            var option = $('<option>');
            option.val(objetivo.id);  // Define o valor da opção para o ID do objetivo
            option.text(objetivo.texto);
            if (objetivo.id == objetivoOriginal) {
                option.prop('selected', true);
            }
            select.append(option);
        });

        // Agora, também atualizamos as outras partes da página
        $('#descricao_div').text(data.descricao_empresa);
        $('#cargos_div').text(data.usuarios.join(', '));
        $('#okrs_div').text(data.objetivos.join(', '));
        $('#krs_div').text(data.krs.join(', '));
        $('#macroacoes_div').text(data.macro_acoes.join(', '));

        // Atualize o campo oculto 'id_okr' para refletir o primeiro objetivo na lista, a menos que um objetivo original esteja definido
        if (objetivoOriginal) {
            $('#id_okr').val(objetivoOriginal);
        } else {
            $('#id_okr').val($('#objetivo').val());
        }
    });
}
