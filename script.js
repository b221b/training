<script>
        function showSchedule() {
            var weekdaySelect = document.getElementById('weekday');
            var selectedItem = weekdaySelect.selectedIndex;
            var responseDiv = document.getElementById('response');

            var responseText = '';
            switch (selectedItem) {
                
                    // +-----------------------------------------------------------------+
                    // |                             1 ДЕНЬ                              |
                    // +-----------------------------------------------------------------+

                case 0:
                    responseText = `<pre><b>ТРЕНИРОВКА СПИНА + ГРУДЬ:</b>

1)спина:
    1)разминка
        5 разминочных подтягиваний параллельным хватом
        50 подтягиваний разными хватами

    2) тяга блока к груди (подбородку) :
        4 подхода:
            1) разминочный вес на 10 повторений (32 кг)
            2) 80% от своего веса на 8 повторений (53кг)
            3) 110% от своего веса на 1-2 повторений (71 кг)
            4) половина от веса в 3 на 30 повторений (35кг)

    3) горизонтальная тяга:
        подходы:
            1) разминочный вес на 10 повторений
            2) +10кг на 10 повторений

    4) экстензия на поясницу
        подходы:
            4х10-15

    5)вертикально-горизонтальная тяга:
        подходы:
            1)45кг 15 повт.
            2)54кг 12 повт.
            3)68кг 8-12 повт
            4)68кг 8-12 повт

2) грудь:
    1) жим лежа
        1) пустой гриф 15-20 повт (разминочный)
        2) 30 кг 8-12 повт.
        3) 45 6-8 повт.
        4) 30 кг 8-12 повт.

    2) жим в тренажере chest press
        1) легкий вес 10-15 повт.
        2) 30 кг 8-10 повт.
        3) 40 кг 8-12 повт.
        4) 50 кг 8 повт.
        5) 50кг макс --> 40кг макс --> 30кг макс --> 20кг макс --> 10 кг макс

    3) разводки в блоках
        1) легкий 15-20 повт (разминочный)
        2) 18 кг 8-12 повт.
        3) 23 кг 4 повт.
        4) 14 кг 15 повт.

    4)пекторал машина:
        подходы:
            1)15кг 15 повт
            2)30кг 8 повт
            3)35кг 5 повт
</pre>`;
                    break;

                    // +-----------------------------------------------------------------+
                    // |                             2 ДЕНЬ                              |
                    // +-----------------------------------------------------------------+

                case 1:
                    responseText = `<pre><b>ТРЕНИРОВКА РУК:</b>

1) трицепс:
    жим лежа узким хватом:
        1)(пустой гриф) 10-15 повт.
        2) 30 кг 10-12 повт.
        3) два подхода 45 кг на макс
        4) 30 кг на макс

2)бицепс:
    тренажер на бицепс:
        подходы:
            1) 0кг 15-20 повт.
            2) 10 кг 8-12 повт.
            3) 10 кг 8-12 повт.
            4) 10 кг 8-12 повт.

3) трицепс:            
    брусья:
        1) 10 повт.
        2) максимум
        3) максимум
        4) максимум

4) бицепс:
    на тренажере сидя
    50 раз, 5 на каждую, вторая отдыхает
 
5) трицепс:
    канат:
        1) легкий вес - 12 повт
        2) легкий вес - 20 повт
        3) легкий вес - макс
        4) легкий вес – макс

6) бицепс:
    гантель на бицепс:
        1) легкий вес - 12 повт
        2) хх вес - 20 повт
        3) хх вес - макс
        4) хх вес – макс
</pre>`;
                    break;
                    
                    // +-----------------------------------------------------------------+
                    // |                             3 ДЕНЬ                              |
                    // +-----------------------------------------------------------------+

                case 2:
                    responseText = `<pre><b>ТРЕНИРОВКА НОГИ + ПЛЕЧИ:</b>

1)ноги:
    1)жим ногами:
        1) разминочный 30кг на 15-20 повт.
        2) 50кг на 8-12
        3) 70кг на 8-12
        4) 90кг на 8-12

    2)гакк машина
        1) 30 кг разминочные 20 повт.
        2) 50 кг на 8-12 повт
        3) 70 кг на 8-12 повт
        4) 90 кг на 8-12 повт

    3)Разгибание ног сидя
        1) хх кг разминочные 20 повт.
        2) хх кг на 8-12 повт
        3) хх кг на 8-12 повт
        4) хх кг на 8-12 повт

    4)Сгибание ног лежа
        1) хх кг разминочные 20 повт.
        2) хх кг на 8-12 повт
        3) хх кг на 8-12 повт
        4) хх кг на 8-12 повт

    5)Сгибание ног сидя
        1) хх кг разминочные 20 повт.
        2) хх кг на 8-12 повт
        3) хх кг на 8-12 повт
        4) хх кг на 8-12 повт

2)плечи:
    1) жим вверх на средний пучок:
        1) разминочный 10кг на 10-12 повт.
        2) 15 кг на 8-12
        3) 20 кг на 8-12
        4) 20 кг делаем максимум --> снимаем по блину, максимум повторений -> снимаем по блину и так пока блинов не останется, тогда максимум

    2) махи в стороны
        1) 8 кг 8-12
        2) 10 кг 8-12
        3) 12 кг 8-12
        4) 14 кг 6-8

    3) протяжки:
        1) хх кг 8-12
        2) хх кг 8-12
        3) хх кг 8-12
        4) хх кг 6-8

    4) средний пучок в кроссовере
        1) 9 кг 8-12
        2) 9 кг 8-12
        3) 14 кг 8-12
        4) 14 кг 6-8

3) предплечья:
    1) скручивание на скамье:
        1) 5 кг 20 повт
        2) 10 кг 8-12 повт.
        3) 10 кг 8-12 повт.
        4) 10 кг 8-12 повт.
</pre>`;
                    break;
                    
                    // +-----------------------------------------------------------------+
                    // |                             4 ДЕНЬ                              |
                    // +-----------------------------------------------------------------+

                case 3:
                    responseText = `<pre><b>ТРЕНИРОВКА СПИНА ГРУДЬ ПЛЕЧИ</b>

1) спина:
    1)Тяга в наклоне:
        1) 30 кг на 10-15 повт.
        2) 50 кг на 8-12
        3) 50 кг на 8-12
        4) 50 кг на 8-12

    2) горизонтальная тяга:
        1) разминочный вес на 10 повторений
        2) +10кг на 10 повторений

2) грудь:
    1) жим в тренажере chest press
        1) легкий вес 10-15 повт.
        2) 30 кг 8-10 повт.
        3) 40 кг 8-12 повт.
        4) 50 кг 8 повт.
        5) 50кг макс --> 40кг макс --> 30кг макс --> 20кг макс --> 10 кг макс

    2) разводки в блоках
        1) легкий 15-20 повт (разминочный)
        2) 18 кг 8-12 повт.
        3) 23 кг 4 повт.
        4) 14 кг 15 повт.

3) плечи:
    1) махи в стороны
            1) 8 кг 8-12
            2) 10 кг 8-12
            3) 12 кг 8-12
            4) 14 кг 6-8

    2) протяжки
        1) легкий 15-20 повт (разминочный)
        2) хх кг 8-12 повт.
        3) хх кг 4 повт.
        4) хх кг 15 повт.
</pre>`;
                    break;
                    
                    // +-----------------------------------------------------------------+
                    // |                             5 ДЕНЬ                              |
                    // +-----------------------------------------------------------------+

                case 4:
                    responseText = `<pre><b>ТРЕНИРОВКА ГРУДЬ НОГИ ТРИЦЕПС БИЦЕПС</b>

1)Грудь:
    1) жим лежа:
            1) пустой гриф 15-20 повт (разминочный)
            2) 30 кг 8-12 повт.
            3) 45 6-8 повт.
            4) 30 кг 8-12 повт.

    2)Жим гантелей лежа на наклонной скамье:
            1) разминочный ххкг на 10-15 повт.
            2) хх кг на 8-12
            3) хх кг на 8-12
            4) хх кг на 8-12

2)Ноги:
    1)Подъем на носки стоя в гакк:
            1) пустой на 10-15 повт.
            2) хх кг на 8-12
            3) хх кг на 8-12
            4) хх кг на 8-12

3)Трицепс:
    1)Жим гантелей за головой: 
            1) 10 кг 8-12
            2) 10 кг 8-12
            3) 10 кг 8-12
            4) 10 кг 8-12

4)Ноги:
    1)Разгибание ног в тренажере: 
            1) хх кг 8-12
            2) хх кг 8-12
            3) хх кг 8-12
            4) хх кг 8-12

5)Бицепс:
    1)Со штангой на бицепс: 
            1) хх кг 8-12
            2) хх кг 8-12
            3) хх кг 8-12
            4) хх кг 8-12
</pre>`;
                    break;
                default:
                    responseText = `<pre>Пожалуйста, выберите день недели</pre>`;
                    break;
            }
            responseDiv.innerHTML = responseText; 
            responseDiv.style.color = '#000'; 
        }

        function clearFields() {
            document.getElementById('response').innerHTML = ''; 
        }
    </script>