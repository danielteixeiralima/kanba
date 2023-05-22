$(document).ready(function(){
    $('.dropdown').hover(function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeIn(500);
    }, function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeOut(500);
    });

    // Adiciona um listener de evento 'change' para o elemento de seleção da empresa
    $('#empresa').change(updateObjectives);

    // Chama a função updateObjectives quando a página é carregada
    updateObjectives();
});

function updateObjectives() {
    var empresaId = $('#empresa').val();
    $.getJSON('/get_objectives/' + empresaId, function(data) {
        var select = $('#objetivo');
        select.empty();
        data.forEach(function(objetivo) {
            var option = $('<option>');
            option.val(objetivo.id);
            option.text(objetivo.objetivo);
            select.append(option);
        });
    });
}
